# -*- coding: utf-8 -*-
from __future__ import with_statement
import time
from sqlite3 import dbapi2 as sqlite3
from hashlib import md5
from datetime import datetime
from contextlib import closing
from flask import Flask, request, session, url_for, redirect, \
     render_template, abort, g, flash
from werkzeug import check_password_hash, generate_password_hash


# configuration
DATABASE = '/tmp/ubet.db'
DEBUG = True
SECRET_KEY = 'development key'

# create our little application :)
app = Flask(__name__)
app.config.from_object(__name__)
app.config.from_envvar('MINITWIT_SETTINGS', silent=True)


class DBObj(object):
    def __init__(self, row):
        for k, v in row.iteritems():
            setattr(self, k, v)

    @classmethod
    def load(cls, object_id):
        row = query_db('''select * from %s where %s_id = ?''' %
            (cls.table, cls.table), [object_id], one=True)
        if row:
            return cls(row)
        raise Exception('DB Object not found')

    @classmethod
    def load_list(cls, query='', args=()):
        return [cls(row) for row in query_db('''select * from %s %s''' %
            (cls.table, query), args)]


class Proposition(DBObj):
    table = 'proposition'

    STATE_INITIAL = 0
    STATE_TRUE = 1
    STATE_FALSE = 2

    @property
    def settled(self):
        return self.state != self.STATE_INITIAL

    @property
    def true(self):
        return self.state == self.STATE_TRUE

    @property
    def false(self):
        return self.state == self.STATE_FALSE

    @property
    def state_string(self):
        if self.state == self.STATE_INITIAL:
            return 'Unsettled'
        elif self.state == self.STATE_TRUE:
            return 'True'
        elif self.state == self.STATE_FALSE:
            return 'False'
        return 'Undefined state'


class Bet(DBObj):
    table = 'bet'

    STATE_INITIAL = 0
    STATE_ACCEPTED = 1
    STATE_NOT_ACCEPTED = 2
    STATE_EXPIRED = 3

    @property
    def proposition(self):
        if not hasattr(self, '_proposition'):
            self._proposition = Proposition.load(self.proposition_id)
        return self._proposition

    @property
    def text(self):
        return self.proposition.text

    def state_string(self, user):
        if self.state == self.STATE_INITIAL:
            return "Proposed"
        elif self.state == self.STATE_EXPIRED:
            return "Proposal expired"
        elif self.state == self.STATE_NOT_ACCEPTED:
            return "Proposal rejected"
        elif self.won(user):
            return "Won"
        elif self.lost(user):
            return "Lost"
        elif self.state == self.STATE_ACCEPTED:
            return "Proposal accepted"
        return "Undefined state"

    def can_accept(self, user):
        return user.user_id != self.user_proposed and \
            user.user_id in [self.user_true, self.user_false] and \
            self.state == self.STATE_INITIAL

    def won(self, user):
        if self.state != self.STATE_ACCEPTED:
            return False

        if self.proposition.state == Proposition.STATE_INITIAL:
            return False

        if (self.proposition.state == Proposition.STATE_TRUE and
            self.user_true == user.user_id):
            return True

        if (self.proposition.state == Proposition.STATE_FALSE and
            self.user_false == user.user_id):
            return True

        return False

    def lost(self, user):
        if self.state != self.STATE_ACCEPTED:
            return False

        if self.proposition.state == Proposition.STATE_INITIAL:
            return False

        if (self.proposition.state == Proposition.STATE_TRUE and
            self.user_false == user.user_id):
            return True

        if (self.proposition.state == Proposition.STATE_FALSE and
            self.user_true == user.user_id):
            return True

        return False


class User(DBObj):
    table = 'user'


def connect_db():
    """Returns a new connection to the database."""
    return sqlite3.connect(DATABASE)


def init_db():
    """Creates the database tables."""
    with closing(connect_db()) as db:
        with app.open_resource('schema.sql') as f:
            db.cursor().executescript(f.read())
        db.commit()

    with closing(connect_db()) as db:
        users = [
            'greg_lange greg@mail.com pass'.split(),
            'kevin_lange kevin@mail.com pass'.split(),
            'clint_lange clint@mail.com pass'.split(),
        ]

        for user in users:
            db.execute('''insert into user (
                username, email, pw_hash) values (?, ?, ?)''',
                [user[0], user[1], generate_password_hash(user[2])])
        db.commit()


def query_db(query, args=(), one=False):
    """Queries the database and returns a list of dictionaries."""
    cur = g.db.execute(query, args)
    rv = [dict((cur.description[idx][0], value)
               for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv


def get_user_id(username):
    """Convenience method to look up the id for a username."""
    rv = g.db.execute('select user_id from user where username = ?',
                       [username]).fetchone()
    return rv[0] if rv else None


def format_datetime(timestamp):
    """Format a timestamp for display."""
    return datetime.utcfromtimestamp(timestamp).strftime('%Y-%m-%d @ %H:%M')


def gravatar_url(email, size=80):
    """Return the gravatar image for the given email address."""
    return 'http://www.gravatar.com/avatar/%s?d=identicon&s=%d' % \
        (md5(email.strip().lower().encode('utf-8')).hexdigest(), size)


@app.before_request
def before_request():
    """Make sure we are connected to the database each request and look
    up the current user so that we know he's there.
    """
    g.db = connect_db()
    g.user = None
    if 'user_id' in session:
        g.user = query_db('select * from user where user_id = ?',
                          [session['user_id']], one=True)


@app.teardown_request
def teardown_request(exception):
    """Closes the database again at the end of the request."""
    if hasattr(g, 'db'):
        g.db.close()


@app.route('/')
def main():
    if g.user:
        return redirect(url_for('my_propositions'))
    return redirect(url_for('login'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    """Logs the user in."""
    if g.user:
        return redirect(url_for('main'))
    error = None
    if request.method == 'POST':
        user = query_db('''select * from user where
            username = ?''', [request.form['username']], one=True)
        if user is None:
            error = 'Invalid username'
        elif not check_password_hash(user['pw_hash'],
                                     request.form['password']):
            error = 'Invalid password'
        else:
            flash('You were logged in')
            session['user_id'] = user['user_id']
            return redirect(url_for('my_propositions'))
    return render_template('login.html', error=error)


@app.route('/register', methods=['GET', 'POST'])
def register():
    """Registers the user."""
    if g.user:
        return redirect(url_for('main'))
    error = None
    if request.method == 'POST':
        if not request.form['username']:
            error = 'You have to enter a username'
        elif not request.form['email'] or \
                 '@' not in request.form['email']:
            error = 'You have to enter a valid email address'
        elif not request.form['password']:
            error = 'You have to enter a password'
        elif request.form['password'] != request.form['password2']:
            error = 'The two passwords do not match'
        elif get_user_id(request.form['username']) is not None:
            error = 'The username is already taken'
        else:
            g.db.execute('''insert into user (
                username, email, pw_hash) values (?, ?, ?)''',
                [request.form['username'], request.form['email'],
                 generate_password_hash(request.form['password'])])
            g.db.commit()
            flash('You were successfully registered and can login now')
            return redirect(url_for('login'))
    return render_template('register.html', error=error)


@app.route('/my_bets')
def my_bets():
    if 'user_id' not in session:
        abort(401)
    user = User.load(session['user_id'])
    bets = Bet.load_list('''where user_true = ? or user_false = ?
        order by created desc''', [session['user_id'], session['user_id']])
    return render_template('my_bets.html', bets=bets, user=user)


@app.route('/my_propositions')
def my_propositions():
    if 'user_id' not in session:
        abort(401)
    propositions = Proposition.load_list('''where author_id = ?
        order by created desc''', [session['user_id']])
    return render_template('my_propositions.html', propositions=propositions)


@app.route('/add_proposition', methods=['POST'])
def add_proposition():
    if 'user_id' not in session:
        abort(401)
    if request.form['text']:
        g.db.execute('''insert into proposition
            (created, author_id, text, state)
            values (?, ?, ?, ?)''',
            [int(time.time()), session['user_id'], request.form['text'],
            Proposition.STATE_INITIAL])
        g.db.commit()
        flash('Your proposition was added.')
    return redirect(url_for('my_propositions'))

@app.route('/settle_proposition', methods=['POST'])
def settle_proposition():
    if 'user_id' not in session:
        abort(401)

    proposition = Proposition.load(request.form['proposition_id'])

    if request.form['truth'] == 'true':
        state = Proposition.STATE_TRUE
    elif request.form['truth'] == 'false':
        state = Proposition.STATE_FALSE
    else:
        abort(500)

    g.db.execute('''update proposition set state = ?
        where proposition_id = ?''', [state, proposition.proposition_id])
    g.db.execute('''update bet set state = ?
        where proposition_id = ? and state = ?''',
        [Bet.STATE_EXPIRED, proposition.proposition_id, Bet.STATE_INITIAL])
    g.db.commit()

    return redirect(url_for('proposition',
       prop_id=proposition.proposition_id))


@app.route('/proposition/<int:prop_id>')
def proposition(prop_id):
    if 'user_id' not in session:
        abort(401)

    user = User.load(session['user_id'])

    proposition = Proposition.load(prop_id)

    users = User.load_list('where user_id != ? order by username',
        [session['user_id']])

    bets = Bet.load_list('where proposition_id = ? order by created desc',
        [prop_id])

    return render_template('proposition.html', bets=bets,
        proposition=proposition, user=user, users=users)


@app.route('/add_bet', methods=['POST'])
def add_bet():
    if 'user_id' not in session:
        abort(401)

    proposition = Proposition.load(request.form['proposition_id'])

    if not proposition:
        abort(500)

    if request.form['truth'] == 'true':
        user_true = session['user_id']
        user_false = request.form['user_id']
    elif request.form['truth'] == 'false':
        user_true = request.form['user_id']
        user_false = session['user_id']
    else:
        abort(500)

    g.db.execute('''insert into bet
        (created, proposition_id, user_proposed, user_true, user_false, state)
        values (?, ?, ?, ?, ?, ?)''',
        [int(time.time()), proposition.proposition_id, session['user_id'],
        user_true, user_false, Bet.STATE_INITIAL])
    g.db.commit()

    return redirect(url_for('proposition',
       prop_id=proposition.proposition_id))


@app.route('/accept_bet', methods=['POST'])
def accept_bet():
    if 'user_id' not in session:
        abort(401)

    bet = Bet.load(request.form['bet_id'])

    if session['user_id'] == bet.user_proposed:
        abort(500)

    if not session['user_id'] in [bet.user_true, bet.user_false]:
        abort(500)

    if request.form['accept'] == 'true':
        state = Bet.STATE_ACCEPTED
    elif request.form['accept'] == 'false':
        state = Bet.STATE_NOT_ACCEPTED
    else:
        abort(500)

    g.db.execute('''update bet set state = ? where bet_id = ?''',
        [state, bet.bet_id])
    g.db.commit()

    return redirect(url_for('my_bets'))


@app.route('/logout')
def logout():
    """Logs the user out."""
    flash('You were logged out')
    session.pop('user_id', None)
    return redirect(url_for('main'))


# add some filters to jinja
app.jinja_env.filters['datetimeformat'] = format_datetime
app.jinja_env.filters['gravatar'] = gravatar_url


if __name__ == '__main__':
    #init_db()
    app.run(host="0.0.0.0")
