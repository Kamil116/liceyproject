from flask import Flask, render_template, url_for, request, redirect, flash
from flask_wtf import FlaskForm
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import login_user, LoginManager, UserMixin, login_required, logout_user, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from wtforms import StringField, SubmitField, TextAreaField, BooleanField, PasswordField
from wtforms.validators import DataRequired

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'a really really really really long secret key'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).get(user_id)


class User(db.Model, UserMixin):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=True)
    password_hash = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Password(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user = db.Column(db.Text, nullable=True)
    site = db.Column(db.Text, nullable=True)
    passw = db.Column(db.Text, nullable=True)


class LoginForm(FlaskForm):
    username = StringField("Имя пользователя", validators=[DataRequired()])
    password = PasswordField("Пароль", validators=[DataRequired()])
    # remember = BooleanField("Запомнить логин")
    submit = SubmitField()


@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')


@app.route('/parols')
@login_required
def parols():
    parols_list = db.session.query(Password).all()
    true_elems = []
    for elem in parols_list:
        if elem.user == current_user.username:
            true_elems.append(elem)
    for i in range(len(true_elems)):
        print(true_elems[i])
    return render_template('parols.html', parols=true_elems)


@app.route('/logout/')
@login_required
def logout():
    logout_user()
    flash("Вы вышли из аккаунта.")
    return redirect(url_for('login'))


@app.route('/parols/<int:id>')
def post_detail(id):
    parol = Password.query.get(id)
    return render_template('parol_detail.html', parol=parol)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if current_user.is_authenticated:
        return redirect('/')
    form = LoginForm()
    if form.validate_on_submit():
        user = db.session.query(User).filter(User.username == form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect('/')
        flash('Неверный логин или пароль', 'error')
        return redirect(url_for('login'))
    return render_template('login.html', form=form)


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['Username']
        hash = generate_password_hash(request.form['Password'])
        date = datetime.utcnow()
        user = User(username=username, password_hash=hash, date=date)
        array = list(db.session.query(User.username).all())
        for elem in array:
            if str(username) == str(elem[0]):
                flash('Введёное имя пользователя уже занято', 'error')
                return redirect('/register')
        try:
            db.session.add(user)
            db.session.commit()
            return redirect('/login')
        except:
            return 'При добавлении пароля возникла ошибка'
    return render_template('register.html')


@app.route('/parols/<int:id>/del')
def parol_delete(id):
    parol = Password.query.get_or_404(id)
    try:
        db.session.delete(parol)
        db.session.commit()
        return redirect('/parols')
    except:
        return 'При удалении возникла ошибка'


@app.route('/parols/<int:id>/update', methods=['POST', 'GET'])
def parol_update(id):
    parol = Password.query.get(id)
    if request.method == 'POST':
        parol.site = request.form['title']
        parol.passw = request.form['text']
        try:
            db.session.commit()
            return redirect('/parols')
        except:
            return 'При редактировании статьи возникла ошибка'
    else:
        return render_template('parol_update.html', parol=parol)


@app.route('/create-parol', methods=['POST', 'GET'])
@login_required
def create_parol():
    global cur
    if request.method == 'POST':
        try:
            title = request.form['title']
            text = request.form['text']
            parol = Password(user=current_user.username, site=title, passw=text)
            db.session.add(parol)
            print('false')
            db.session.commit()
            print('true')
            return redirect('/parols')
        except:
            return 'При добавлении пароля возникла ошибка'
    else:
        return render_template('create-parol.html')


if __name__ == '__main__':
    app.run(debug=True)
