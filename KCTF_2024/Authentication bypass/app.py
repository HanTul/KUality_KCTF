from flask import Flask, request, render_template, make_response, redirect, session, url_for, abort
from models import db, Kuser, Board
import os, hashlib


app = Flask(__name__)
app.secret_key = os.urandom(24)
admin_code = os.urandom(24)

try:
    FLAG = open('flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

def get_current_user():
    user = session.get('user_id')
    if user:
        return Kuser.query.filter_by(username=user).first()
    return None

def check_session(route=None):
    if "user_id" in session:
            return '<script>alert("잘못된 접근입니다."); history.go(-1)</script>'
    else:
        return render_template(route) if route else None

def encrypt_password(password):
    salt = os.urandom(16)
    pw_hash = hashlib.sha256(password.encode() + salt)
    encrypted_pw = pw_hash.hexdigest()
    return encrypted_pw

@app.route('/')
def index():
    return render_template("index.html", user=get_current_user().username if get_current_user() else None)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return check_session("register.html")
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        re_password = request.form.get('re_password')
        user = Kuser.query.filter_by(username=username).first()
        if password != re_password:
            return '<script>alert("비밀번호가 일치하지 않습니다."); history.go(-1)</script>'
        else:
            if not user:
                encrypted_pw = encrypt_password(password)
                kuser = Kuser(username=username, password=encrypted_pw, permission='user')
                db.session.add(kuser)
                db.session.commit()
                return render_template('register.html', username=username, password=encrypted_pw)
            else:
                return '<script>alert("이미 존재하는 유저입니다."); history.go(-1)</script>'


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return check_session("login.html")
    else:
        username = request.form.get('username')
        password = request.form.get('password')
        user_data = Kuser.query.filter_by(username=username, password=password).first()
        if user_data is not None:
            session['user_id'] = username
            resp = make_response(redirect('/'))
            return resp
        else:
            username = Kuser.query.filter_by(username=username).first()
            if username is None:
                return '<script>alert("존재하지 않는 유저입니다."); history.go(-1)</script>'
            else:
                return '<script>alert("비밀번호가 일치하지 않습니다."); history.go(-1)</script>'


@app.route('/logout', methods=['GET'])
def logout():
    session.clear()
    return redirect('/')

@app.route('/profile', methods=['GET', 'POST'])
def profile(admin_check='N', message=None):
    if "user_id" not in session:
        return '<script>alert("잘못된 접근입니다."); history.go(-1)</script>'
    
    current_user = get_current_user()

    if current_user and current_user.permission == 'admin':
        admin_check = 'Y'

    return render_template("profile.html", user=current_user, username=current_user.username, permission=current_user.permission, admin_check=admin_check, message=message)
    

@app.route('/authentication', methods=['POST'])
def authentication():
    if "user_id" not in session:
         return '<script>alert("잘못된 접근입니다."); history.go(-1)</script>'
    
    current_user = get_current_user()
    action = request.form.get('action')
    admin_check = request.form.get('admin_check')
    try:
        input_code = int(request.form.get('input_code'))
    except (ValueError, TypeError):
        input_code = None

    if action == "authentication":
        if input_code == admin_code:
            return profile(admin_check='Y', message='코드가 확인되었습니다.')
        else:
            return '<script>alert("잘못된 코드입니다."); history.go(-1)</script>'
    
    elif action == "get_admin" and admin_check == 'Y':
        if current_user:
            current_user.permission = 'admin'
            db.session.commit() 
            return '<script>alert("관리자 권한이 부여되었습니다."); window.location.href = "/profile";</script>'
    else:
        return '<script>alert("잘못된 요청입니다."); history.go(-1)</script>'


@app.route('/board', methods=['GET'])
def board():
    current_user = get_current_user()

    if "user_id" not in session:
        return '<script>alert("잘못된 접근입니다."); history.go(-1)</script>'
    
    posts = Board.query.order_by(Board.id.asc()).all()
    return render_template("board.html", user=current_user, permission = current_user.permission, posts=posts)
    
@app.route('/board/<int:post_id>', methods=['GET'])
def post_detail(post_id):
    post = Board.query.get_or_404(post_id)
    current_user = get_current_user()
    if post.is_secret:
        if current_user.permission != 'admin':
            return '<script>alert("열람 권한이 없습니다."); history.go(-1)</script>'
        else:
            return render_template('post_detail.html', post=post, flag=FLAG)
    else:
        return render_template('post_detail.html', post=post, flag=None)


if __name__ == '__main__':
    basedir = os.path.abspath(os.path.dirname(__file__))
    dbfile = os.path.join(basedir, 'db.sqlite')
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + dbfile
    app.config['SQLALCHEMY_COMMIT_ON_TEARDOWN'] = True 
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000)
