from flask import Flask, _app_ctx_stack, g, session, redirect, url_for, render_template, abort, flash, request
from sqlite3 import dbapi2 as sqlite3
from datetime import datetime
from hashlib import md5
import time
from werkzeug.security import generate_password_hash, check_password_hash

DATABASE = '/tmp/mytwit.db'
PER_PAGE = 30
SECRET_KEY = 'development key'

app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MYTWIT_SETTINGS', silent=True)


@app.cli.command('initdb')
def initdb_command():
    init_db()
    print('init db')


def init_db():
    db = get_db()
    with app.open_resource('schema.sql', mode='r') as f:
        db.cursor().executescript(f.read())
    db.commit()


def get_db():
    top = _app_ctx_stack.top
    if not hasattr(top, 'sqlite_db'):
        top.sqlite_db = sqlite3.connect(app.config['DATABASE'])
        top.sqlite_db.row_factory = sqlite3.Row
    return top.sqlite_db


@app.teardown_appcontext
def close_database(exception):
    top = _app_ctx_stack.top
    if hasattr(top, 'sqlite_db'):
        top.sqlite_db.close()


def query_db(query, args=(), one=False):
    print ('query: ' + query)
    print ('args: ' + str(args))
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    rv = query_db('select user_id from user where username=(?)', [username], True)
    return rv


def format_datetime(timestamp):
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    return 'http:///www.gravatar.com/avatar/{}?d=identicon&s={}' \
        .format(md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = query_db('SELECT * FROM user WHERE user_id = ?'
                          , [session['user_id']], True)


@app.route('/')
def timeline():
    if not g.user:
        return redirect(url_for('public_timeline'))
    query = '''
        SELECT message.*, user.* FROM message, user
        WHERE message.author_id=user.user_id AND 
        (user.user_id=? OR user.user_id IN (SELECT whom_id FROM 
        follower WHERE who_id=?)) ORDER BY message.pub_date DESC LIMIT (?)
    '''
    messages = query_db(query, (session['user_id'], session['user_id'], PER_PAGE))
    return render_template('layout.html', messages=messages)


@app.route('/public')
def public_timeline():
    query = '''
        SELECT message.*,user.* FROM message,user
        WHERE message.author_id=user.user_id
        ORDER BY message.pub_date DESC LIMIT ? '''
    messages = query_db(query, [PER_PAGE])
    return render_template('timeline.html', messages=messages)


@app.route('/<username>')
def user_timeline(username):
    profile_user = query_db('SELECT * FROM user WHERE username=?', [username], one=True)
    if profile_user is None:
        abort(404)
    followed = False
    if g.user:
        follow_query = '''
            SELECT * FROM follower WHERE follower.who_id=? AND follower.whom_id=?
        '''
        followed = query_db(follow_query, (session['user_id'], profile_user['user_id']), True) is not None
    content_query = '''
        SELECT message.*, user.* FROM message, user WHERE user.user_id=message.author_id AND user.user_id=?
        ORDER BY message.pub_date DESC LIMIT ?
    '''
    messages = query_db(content_query, (profile_user['user_id'], PER_PAGE))
    return render_template('timeline.html', messages=messages, followed=followed, profile_user=profile_user)


@app.route('/<username>/follow')
def follow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('INSERT INTO follower (who_id,whom_id) VALUES (?,?)', (session['user_id'], whom_id))
    db.commit()
    flash('You are now following {}'.format(username))
    return redirect(url_for('user_timeline', username=username))


@app.route('/<username>/unfollow')
def unfollow_user(username):
    if not g.user:
        abort(401)
    whom_id = get_user_id(username)
    if whom_id is None:
        abort(404)
    db = get_db()
    db.execute('DELETE FROM follower WHERE who_id=? AND whom_id = ?', (session['user_id'], whom_id))
    db.commit()
    flash('You are no longer following {}'.format(username))
    return redirect(url_for('user_timeline', username=username))


@app.route('/add_message', methods=['POST'])
def add_message():
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        db = get_db()
        db.execute('INSERT INTO message (author_id, text, pub_date) VALUES (?,?,?)',
                   (session['user_id'], request.form['text'], int(time.time())))
        db.commit()
        flash('Your message was recorded')
    return redirect(url_for('timeline'))


@app.route('/loigin', methods=['POST', 'GET'])
def login():
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        user = query_db('SELECT * FROM user WHERE username=?', (request.form['username'],), one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'], request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('timeline'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    if g.user:
        return redirect(url_for('timeline'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or '@' not in request.form['email']:
            error = 'You have to enter a invalid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            db = get_db()
            db.execute('INSERT INTO user (username,email,pw_hash) VALUES (?,?,?)',
                       (request.form['username'], request.form['email'],
                        generate_password_hash(request.form['password'])))
            db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for(login))
    return render_template('register.html', error=error)


@app.route('/logout')
def logout():
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('public_timeline'))


app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url