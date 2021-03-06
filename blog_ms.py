#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Thu Jan 13 13:46:56 2022

@author: mertsamast
"""
from functools import wraps
from crypt import methods
from http.client import NETWORK_AUTHENTICATION_REQUIRED
import socket
from turtle import title
from unittest import result
from flask import Flask, render_template, flash, redirect, url_for, session, logging, request
import pymysql
from pymysql.cursors import Cursor
from wtforms import Form, StringField,TextAreaField,PasswordField,validators
from passlib.handlers.sha2_crypt import sha256_crypt
from pymysql import cursors
from flask_mysqldb import MySQL
#from flaskext.mysql import MySQL
import mysql.connector as ms
import mysql as NG
from mysql import connector
import MySQLdb



##Kullanıcı girişi kontrol decorator##
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" in session:      #kulanıcı giriş yapmışsa, istenilen sayfaya erişebilir.
            return f(*args, **kwargs)
        else:                           #kullanıcı giriş yapmamışsa, istenilen sayfaya erişemez. Giriş yapması gerektiği söylenir.
            flash("Bu sayfayı görüntülemek için giriş yapmanız gerekli.", "danger")
            return redirect(url_for("login"))
    return decorated_function


## Kullanıcı Kayıt Formu Class'ı ##
class register_form(Form):
    name = StringField("İsim Soyisim",validators=[validators.Length(min = 4, max = 20)])         #validators, kullanıcıya mutlaka şifre girin gibi sınırlandırmalar getirir.
    username = StringField("Kullanici Adi",validators=[validators.Length(min = 5, max = 35)])
    email = StringField("E-Mail Adresi",validators=[validators.Email(message="Lutfen Gecerli bir e-mail adresi giriniz.")])
    password = PasswordField("Parola:" ,validators=[validators.DataRequired(message= "Lutfen Bir Parola Belirleyin.."),
    validators.EqualTo(fieldname="confirm", message="Parolaniz Uyusmuyor.")])
    confirm = PasswordField("Parola Dogrula")

## Kullanıcı giriş Form Class'ı ##
class login_form(Form):
    username = StringField("Kullanıcı adı")
    password = PasswordField("Parola")


app = Flask(__name__)

#MySQL için secret key gerekli. Flash mesajları için gerekli
app.secret_key = "msblog"

#MySQL nerde çalışyor;
app.config["MYSQL_HOST"] = "localhost"

#MySQL Veri tabaının kulanıcı ismini vermemiz gerekiyor;
app.config["MYSQL_USER"] = "root"

#MySQL'e bağlanmak için gerekli olan parola;
app.config["MYSQL_PASSWORD"] = ""

#MySQL'in ismini belirtmeliyiz;
app.config["MYSQL_DB"] = "MSBlog"

#Sözlük için cursor yaptık. Böylece sözlükte dolaşıp güzel bir şekilde db'den verileri çekebilecek.
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

#app.config["MYSQL_TCP_PORT"] = "3306"

mysql = MySQL(app)  #boylece app'i, MySQL veri tabanına bağladık.
#mysql.init_app(app)


@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

## Kayıt olma sayfası
@app.route("/register", methods=["GET", "POST"])
def register():
    form = register_form(request.form)

    if request.method == "POST" and form.validate(): #Register form düzgün dolduruldu ise fonksiyona girer. 
        name = form.name.data
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(form.password.data) #Şifreleri bozarak kaydeder.
        
        #cursor = mysql.connection.cursor()
        #cur = ms.connection.MySQLCursor()
        cursor = mysql.connection.cursor()
        #cr = MySQLdb.Connection.cursor()

        #cursor2 = cursors.Cursor()
        #cursor = cursors.Cursor()
        sorgu = "Insert into users (name, email, username, password) VALUES(%s,%s,%s,%s)"
        #cur.execute(sorgu,(name,email,username,password))
        cursor.execute(sorgu,(name,email,username,password))  #demet şeklinde yapmalıyız. DB'ye bu şekilde atıyor.
        mysql.connection.commit()  #Değişiklik yaptığımızda commit etmeliyiz.

        #cursors.Cursor.connection.commit()
        #cursors.Cursor.close()
        #cur.close()
        cursor.close()

        flash("Basari ile kayit oldunuz.","success") #Bir sonraki requestte yayınlanıyor.

        return redirect(url_for("login"))

    else:
        return render_template("register.html", form = form)  #Hem get hem post request alabilir diye belirttik.

#login işlemi.
@app.route("/login", methods= ["GET", "POST"])
def login():
    form = login_form(request.form)
    if request.method == "POST":
        username = form.username.data
        password_entered = form.password.data

        cursor = mysql.connection.cursor()      #Cursor ile veri tabanında dolaşım sağlıyoruz.
        sorgu = "Select * From users where username = %s"       #buna göre sorgu yapılacak.

        result = cursor.execute(sorgu,(username,)) #değer dönecek. kullanıcı yoksa 0 döner.
        if result > 0:      #kullanıcı var ise
            data = cursor.fetchone() #Kullanıcının tüm bilgileri alınmış oluyor.
            real_password = data["password"]    #gerçek parolayı aldık. şifrelenmiş bir şekilde geldi.
            if sha256_crypt.verify(password_entered,real_password):     #şifreleri karşılaştırdı.
                flash("Basari ile giris yapildi.", "success")
                ##giriş kontrolü yapıldı, session oluşturulacak.
                session["logged_in"] = True         #anahtar verildi, true yapıldı.
                session["username"] = username      #kullanıcı adının value'sını, kulanıcı adına atadık.
                return redirect(url_for("index"))
            else:
                flash("Kullanici adi veya parola yanlis. Lutfen Kontrol ediniz.", "danger")
                return redirect(url_for("login"))

        else:   #kullanici yok ise
            flash("Boyle bir kullanici bulunmamaktadir...", "danger")
            return redirect(url_for("login"))
    return render_template("login.html", form = form)

#Log-out işlemleri
@app.route("/logout")
def logout():
    session.clear()         #Kaydı siler.
    return redirect(url_for("index"))

#kontrol paneli
@app.route("/dashboard")
@login_required     #decorator kullanıldı.
def dashboard():
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles where author = %s"         #kendi username'mimizi kullanarak kendimizin oluşturduğu makaleleri çekiyoruz.
    result = cursor.execute(sorgu, (session["username"],))      #cursor'ı execute ederek çalışır hale getirdik. İçerisindeki durumlar çalışacak.

    if result > 0:
        articles = cursor.fetchall()    #liste içinde sölzük olarak aldık.
        return render_template("dashboard.html", articles = articles)
        pass
    else:
        return render_template("dashboard.html")


@app.route("/article/<string:id>")
def detail(id):
    return "Article id: " + id

# Makale Sayfası
@app.route("/articles")
def articles():
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles"        #tüm makaleleri çeker.
    result = cursor.execute(sorgu)

    if result > 0:          #veri tabanında makale var mı?
        articles = cursor.fetcall()         #bütün makaleleri DB'de gördü, yakaladı.
        return render_template("articles.html", articles = articles)
    else:
        return render_template("articles.html")
    #return render_template("articles.html")

# Makale Eklemek
@app.route("/addarticle", methods=["GET", "POST"])
def addarticle():
    form = articleForm(request.form)        #form oluşturduk.
    if request.method == "POST" and form.validate():
        title = form.title.data
        content = form.content.data

        cursor = mysql.connection.cursor()          #DB'de gezmek için cursor oluşturuldu.
        sorgu = "Insert into articles (title, author,content) VALUES(%s%s%s)"       #İstenilen değerler DB2de yazılmak için hazırlandı.
        cursor.execute(sorgu, (title,session["username"],content))      #DB'ye eklendi. Session ile username kontrolü sağlandı.
        mysql.connection.commit()           #değişiklik olacağı için commit etmek gerekli.

        cursor.close()
        flash("Makale başarı ile kaydedilmiştir.", "success")
        return redirect(url_for("dashboard"))

    return render_template("addarticle.html", form = form)

# Makale Silmek
@app.route("/delete/<string:id>")
@login_required
def delete_article(id):
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles where author = %s and id = %s"
    result = cursor.execute(sorgu,(session["username"], id))

    if result > 0:
        sorgu2 = "Delete From articles where id = %s"
        cursor.execute(sorgu2, (id,))
        mysql.connection.commit()
        return redirect(url_for("dashboard"))
    else:
        flash("Böyle bir makale yok veya bu makaleyi silme yetkiniz yok.", "danger")
        return redirect(url_for("index"))

# Makale Düzenlemek.
@app.route("/edit/<string:id>", methods = ["GET", "POST"])
@login_required
def updateArticle(id):
    if request.method == "GET":
        cursor = mysql.connection.cursor()
        sorgu = "Select * From articles wher id = %s and author = %s"
        result = cursor.execute(sorgu, (id, session["username"]))   #sorgumuzu bu kriterlere göre çalıştırdık.

        if result == 0:
            flash("Böyle bir makale yok veya bu işleme yetkiniz bulunmamaktadır.", "danger")
            return redirect(url_for("index"))       #hata alınca ana sayfaya gönderdik.
        else:
            article = cursor.fetchone()     #makalenin şu anki halini aldık. Form oluşturulmalı.
            form = articleForm()
            form.title.data = article["title"]
            form.content.data = article["content"]

            return render_template("update.html", form = form)
    else:
        # Post request kısmı
        form = articleForm(request.form)
        new_title = form.title.data
        new_content = form.content.data

        sorgu2 = "Update articles Set title= %s, content = %s where id = %s"
        cursor = mysql.connection.cursor()
        cursor.execute(sorgu2, (new_title, new_content, id))
        mysql.connection.commit()
        flash("Makale başarı ile güncellendi.", "success")

        return redirect(url_for("dashboard"))

# Detay Sayfası
@app.route("/article/<string:id>")
def detail_aritcle(id):
    cursor = mysql.connection.cursor()
    sorgu = "Select * From articles where id = %s"
    result = cursor.execute(sorgu, (id,))

    if result > 0:
        article = cursor.fetchone()
        return render_template("article.html", article = article)
    else:
        return render_template("article.html")



# Makale Formu oluşturmak.
class articleForm(Form):
    title = StringField("Makale Başlığı", validators=[validators.Length(min = 5, max = 200)])
    content = TextAreaField("Makale İçeriği", validators=[validators.Length(min = 10)])

# Arama URL
@app.route("/search", methods=["GET", "POST"])
#sadece post request olmalı. Çünkü arama yapılacak. Post edilecek.
def search():
    if request.method == "GET":
        return redirect(url_for("index"))
    else:
        keyword = request.form.get("keyword")       #bu keyword, html sayfasından geliyor.
        cursor = mysql.connection.cursor()
        sorgu = "Select * From articles where title like '%" + keyword + "%' "  #keywordde ne yazıldıysa onu aramak için çalıştırılan komut.
        result = cursor.execute(sorgu)

        if result == 0:
            flash("Arana kelimeye uygun bir makale bulunamadı.", "warning")
            return redirect(url_for("articles"))
        else:
            articles = cursor.fetchall()        #hepsini aldık.
            return render_template("articles.html", articles = articles)        #articles.html sayfasına gönderdik.

if __name__ == "__main__":
    app.run(debug=True)
