from flask import Flask, request, render_template, make_response, redirect, session

app = Flask(__name__)

try:
    FLAG = open('flag.txt', 'r').read()
except:
    FLAG = '[**FLAG**]'

app.secret_key = FLAG

users = {
    'kuality': {'pw': FLAG, 'email': 'kuality@nice.com', 'position': '관리자'},
    'user1': {'pw': '1234', 'email': 'test@example.com', 'position': '부원'},
    'user2': {'pw': '5678', 'email': 'test2@example.com', 'position': '부원'}

}

@app.route('/')
def index():
    if "user_ID" in session:
        current_user = session.get('user_ID')
        return render_template("index.html", user_id=current_user)
    else:
        return render_template("index.html", user_id=None)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        if "user_ID" in session:
            current_user = session.get('user_ID')
            return render_template("login.html", user_id=current_user)
        else:
            return render_template("login.html", user_id=None)
    else:
        id = request.form.get('id')
        password = request.form.get('password')
        try:
            pw = users[id]['pw']
        except:
            return '<script>alert("등록되지 않은 유저입니다."); history.go(-1)</script>'
        if password != pw:
            return '<script>alert("잘못된 비밀번호입니다."); history.go(-1)</script>'
        else:
            session['user_ID'] = id
            resp = make_response(redirect('/'))
            return resp

@app.route('/profile')
def profile():
    if "user_ID" in session:
        user_id = request.args.get('user_id')
        pw = users[user_id]['pw']
        email = users[user_id]['email']
        position = users[user_id]['position']
        return render_template("profile.html", user_id=user_id, pw=pw, email=email, position=position)
    else:
        return '<script>alert("잘못된 접근입니다."); history.go(-1)</script>'

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
