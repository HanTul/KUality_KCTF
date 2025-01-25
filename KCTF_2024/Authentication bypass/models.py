from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()           #SQLAlchemy를 사용해 데이터베이스 저장

class Kuser(db.Model): 
    __tablename__ = 'kuser'   #테이블 이름 : fcuser
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)   #id를 프라이머리키로 설정
    username = db.Column(db.String(64), unique=True, nullable = False)
    password = db.Column(db.String(64), nullable = False)     #패스워드를 받아올 문자열길이 
    permission = db.Column(db.String(10), nullable = False)  

class Board(db.Model):
    __tablename__ = 'post'
    id = db.Column(db.Integer, primary_key = True, autoincrement = True)
    title = db.Column(db.String(100), nullable = False)
    content = db.Column(db.Text, nullable = False)
    author = db.Column(db.String(64), db.ForeignKey('kuser.username'), nullable = False)
    is_secret = db.Column(db.Boolean, default=False)
