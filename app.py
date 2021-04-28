from flask import Flask, render_template, url_for, request, redirect, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import login_user
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///parol.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Parol(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=True)
    text = db.Column(db.Text, nullable=True)
    username = db.Column(db.Text, nullable=True)
    password = db.Column(db.Text, nullable=True)
    date = db.Column(db.DateTime, default=datetime.utcnow)


@app.route('/')
@app.route('/home')
def index():
    return render_template('index.html')


@app.route('/parols')
def parols():
    parols = Parol.query.order_by(Parol.date.desc()).all()
    return render_template('parols.html', parols=parols)


@app.route('/parols/<int:id>')
def post_detail(id):
    parol = Parol.query.get(id)
    return render_template('parol_detail.html', parol=parol)


@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']
        if username and password:
            for elem in Parol.query:
                if elem.password == password and elem.username == username:
                    return redirect('/')
    return render_template('login.html')


@app.route('/register', methods=['POST', 'GET'])
def register():
    if request.method == 'POST':
        username = request.form['Username']
        password = request.form['Password']
        date = datetime.utcnow()
        parol = Parol(username=username, password=password, date=date)
        try:
            db.session.add(parol)
            db.session.commit()
            return redirect('/login')
        except:
            return 'При добавлении пароля возникла ошибка'
    return render_template('register.html')


@app.route('/parols/<int:id>/del')
def parol_delete(id):
    parol = Parol.query.get_or_404(id)
    try:
        db.session.delete(parol)
        db.session.commit()
        return redirect('/parols')
    except:
        return 'При удалении возникла ошибка'


@app.route('/parols/<int:id>/update', methods=['POST', 'GET'])
def parol_update(id):
    parol = Parol.query.get(id)
    if request.method == 'POST':
        parol.title = request.form['title']
        parol.text = request.form['text']
        try:
            db.session.commit()
            return redirect('/parols')
        except:
            return 'При редактировании статьи возникла ошибка'
    else:
        return render_template('parol_update.html', parol=parol)


@app.route('/create-parol', methods=['POST', 'GET'])
def create_parol():
    if request.method == 'POST':
        title = request.form['title']
        text = request.form['text']
        u = '23112'
        p = '23132'
        date = datetime.utcnow()
        parol = Parol(title=title, username=u, password=p, text=text, date=date)
        try:
            db.session.add(parol)
            db.session.commit()
            return redirect('/parols')
        except:
            return 'При добавлении пароля возникла ошибка'
    else:
        return render_template('create-parol.html')


if __name__ == '__main__':
    app.run(debug=True)
