from flask import Flask, render_template, url_for, request, redirect, flash
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.exc import IntegrityError
from datetime import datetime
from werkzeug.security import check_password_hash, generate_password_hash

site = Flask(__name__)
site.secret_key = 'bara bara bara bere bere bere'
site.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
site.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
db = SQLAlchemy(site)
manager = LoginManager(site)

def is_user_registered(login):
    return Users.query.filter_by(login=login).first()


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # loguser = db.Column(db.Integer, nullable=False)
    # guest = db.Column(db.Integer, nullable=False)
    # admin = db.Column(db.Integer, nullable=False)
    # lector = db.Column(db.Integer, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    login = db.Column(db.String(255), nullable=False, unique=False)



class Lecture(db.Model, UserMixin):
    nameOfBroadcast = db.Column(db.String, primary_key=True)
    linkForBroadcast = db.Column(db.String, nullable=False)
    lecturerName = db.Column(db.String, nullable=False)
    discipline = db.Column(db.String, nullable=False)
    time = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)

@manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)

    # def __repr__(self):
    #     return '<Article %r>' % self.id

@site.route('/admin', methods=['GET', 'POST'])
def admin_page():
    if request.method == 'POST':
        return add_lecture()

    return render_template("admin.html")

@site.route('/add_lecture', methods=['GET'])
def add_lecture():
    name_of_broadcast = request.form.get('nameOfBroadcast')
    link_for_broadcast = request.form.get('linkForBroadcast')
    lecturer_name = request.form.get('lecturerName')
    discipline = request.form.get('discipline')
    time = request.form.get('time')
    description = request.form.get('description')

    new_lecture = Lecture(
        nameOfBroadcast=name_of_broadcast,
        linkForBroadcast=link_for_broadcast,
        lecturerName=lecturer_name,
        discipline=discipline,
        time=time,
        description=description
    )

    try:
        db.session.add(new_lecture)
        db.session.commit()
        flash('Lecture added successfully!')
    except Exception as e:
        db.session.rollback()
        flash('Error adding lecture. Please try again later.')

    return redirect(url_for('broadcast_page'))

@site.route('/get_current_lecture')
def get_current_lecture():
    current_lecture = Lecture.query.order_by(Lecture.nameOfBroadcast.desc()).first()
    return current_lecture

@site.route('/broadcasts')
def broadcast_page():
    current_lecture = get_current_lecture()
    return render_template("broadcasts.html", current_lecture=current_lecture)

@site.route('/main')
@site.route('/')
@login_required
def main_page():
    with site.app_context():
        db.create_all()
    return render_template("main.html")


@site.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')

    if login and password:
        user = Users.query.filter_by(login=login).first()

        if user and check_password_hash(user.password, password):
            login_user(user)

            next_page = request.args.get('next')

            return redirect(next_page)
        else:
            flash('Login or password is not correct')
    else:
        flash('Please fill login and password fields')
    return render_template('login.html')


@site.route('/logout', methods=['GET', 'POST'])
@login_required
def logout_page():
    logout_user()
    return redirect(url_for('main_page'))  # ну например

@site.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)

    return response


@site.route('/registration', methods=['GET', 'POST'])
def registration_page():
    if request.method == 'POST':
        login = request.form.get('login')
        password = request.form.get('password')
        password2 = request.form.get('password2')

        if login == "" or password == "" or password2 == "":
            flash('Пожалуйста, заполните все поля!')
        elif is_user_registered(login):
            flash("Пользователь с таким логином уже существует")
        elif password != password2:
            flash('Пароли не совпадают')
        else:
            hash_pwd = generate_password_hash(password)
            new_user = Users(login=login, password=hash_pwd)

            try:
                db.session.add(new_user)
                db.session.commit()
                flash('Регистрация успешна!')
                return redirect(url_for('login_page'))
            except IntegrityError:
                db.session.rollback()
                flash('Пользователь с таким логином уже существует')
            except Exception as e:
                db.session.rollback()
                flash('Произошла ошибка при регистрации. Попробуйте позже.')

    return render_template('registration.html')



if __name__ == "__main__":
    site.run(debug=True)