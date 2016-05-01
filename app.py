from flask import (Flask, send_from_directory, abort,
                  render_template, request, flash, redirect)
from flask_sqlalchemy import SQLAlchemy
from random import choice, random
from uuid import uuid4
from datetime import datetime
import json
import logging
from hashlib import sha256
import shutil
import socket
import os
from time import strftime
import settings as SETTINGS

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = SETTINGS.DATABASE_URI
db = SQLAlchemy(app)

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(255))
    name = db.Column(db.String(255), unique=True)
    score = db.Column(db.Integer)
    nsfw = db.Column(db.Boolean)

    def __init__(self, path, name, score=0, nsfw=False):
        self.path = path
        self.name = name
        self.score = score
        self.nsfw = False

    def __repr__(self):
        return '<Video %r (%d)>' % (self.name, self.score)

class Address(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address = db.Column(db.String(64), unique=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

    def __init__(self, address, user=None):
        self.address= address
        self.user = user

    def __repr__(self):
        if self.user:
            un = self.user.username
        else:
            un = "?"
        return '<IP %r (%s)>' % (self.address, un)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True)
    addresses = db.relationship('Address', backref='user', lazy='dynamic')

    def __init__(self, username):
        self.username = username

    def __repr__(self):
        return '<User %r>' % self.username

class Action(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    address_id = db.Column(db.Integer, db.ForeignKey('address.id'))
    video_id = db.Column(db.Integer, db.ForeignKey('video.id'))
    action = db.Column(db.Enum("good", "bad", "view", name="action_type_enum"))
    timestamp = db.Column(db.DateTime)

    address = db.relationship('Address', backref=db.backref('actions', lazy='dynamic'))
    video = db.relationship('Video', backref=db.backref('actions', lazy='dynamic'))

    def __init__(self, address, video, action):
        self.address_id = address.id
        self.video_id = video.id
        self.action = action
        self.timestamp = datetime.utcnow()

    def __repr__(self):
        stamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        if self.address.user:
            un = self.address.user.username
        else:
            un = self.address.address
        return "%s - %s by %s" % (stamp, self.action, un)

try:
    from raven.contrib.flask import Sentry
except ImportError:
    pass
else:
    sentry = Sentry(app)

delta = 0

def map_ips(ip, default):
    with open('addresses.json') as fp:
        addrs = json.load(fp)
        return addrs.get(ip, default)


def get_ip():
    ip = request.environ.get('HTTP_X_REAL_IP')
    if not ip:
        ip = request.remote_addr
    return ip


def add_log(webm, action):
    global delta
    ip = get_ip()
    ip = map_ips(ip, ip)
    string = strftime('%Y-%m-%d %H:%M:%S ' + ip + ' ' + action)
    with open('webms/metadata/' + webm, 'a') as logfile:
        logfile.write(string + '\n')
    print(str(delta) + ' ' + string + ' http://webm.website/' + webm)


def get_user_censured(webm):
    log = get_log(webm)
    if log is not None:
        user = get_ip()
        user = map_ips(user, user)
        log = log.split('\n')
        for line in log:
            if user in line:
                if 'censure' in line:
                    return True
                if 'demote' in line:
                    return True
    return False


def is_unpromotable(webm):
    actions = get_address_video_actions(get_ip(), webm.id)

    #if webm in get_best_webms():
    #    return 'already featured'
    #if webm in get_vetoed_webms():
    #    return 'this video has been vetoed'

    #if user == '(central)':
    #    return 'this shared IP address is banned'
    #if user.startswith('94.119'):
    #    return 'this shared IP address is banned'
    if "good" in actions:
        return 'cannot feature own videos'
    if "bad" in actions:
        return 'you demoted this before!'
    return False


def is_votable(webm):
    actions = get_address_video_actions(get_ip(), webm.id)
    if "good" in actions:
        return 'cannot feature own videos'
    if "bad" in actions:
        return 'you demoted this before!'

    #if 'censure' in line:
    #    return 'you already censured'
    #if 'affirm' in line:
    #    return 'you already affirmed'
    #if 'featured' in line:
    #    return 'you featured this!'
    return False


def get_log(webm):
    #try:
    #    fp = open('webms/metadata/' + webm, 'r')
    #    string = fp.read()
    #    fp.close()
    #    return string
    #except IOError:
    return None


def get_name(webm):
    return os.path.splittext(webm)[0]


def generate_webm_token(webm, salt=None):
    if not salt:
        salt = uuid4().hex
    return sha256(app.secret_key.encode() + webm.name.encode() + salt).hexdigest()+ ':' + salt


def get_all_webms():
    return Video.query.all()

#TODO(samstudio8) 404 on failure
def get_video(name):
    try:
        return Video.query.filter(Video.name == name)[0]
    except IndexError:
        return None

#TODO(samstudio8) Create new user on failure
def get_address(address):
    try:
        return Address.query.filter(Address.address == address)[0]
    except IndexError:
        return None

def get_address_video_actions(raw_ip, webm_id):
    address = get_address(raw_ip)
    if address.user:
        actions = [x[0] for x in Action.query.filter(Action.address_id.in_( address.user.addresses.with_entities(Address.id) ), Action.video_id == webm_id).with_entities(Action.action).all()]
    else:
        actions = [x[0] for x in Action.query.filter(Action.address_id == address.address, Action.video_id == webm_id).with_entities(Action.action).all()]
    return actions

def make_video_history(webm_id):
    return "\n".join([str(x) for x in Action.query.filter(Action.video_id == webm_id).all()])

def get_good_webms():
    return Video.query.filter(Video.score > 1).all()

def get_music_webms():
    return os.listdir('webms/music')


def get_best_webms():
    return os.listdir('webms/best')


def get_vetoed_webms():
    return os.listdir('webms/veto')


def get_bad_webms():
    return Video.query.filter(Video.score < 0).all()


def get_safe_webms():
    return Video.query.filter(Video.nsfw == False).all()

def get_quality_webms():
    """Allows whitelisting of reports to stop the top-tier webms being 403'd"""
    return list(set(get_good_webms()).union(get_best_webms()))


def get_pending_webms():
    return Video.query.filter(Video.score >= 0).all()

def get_trash_webms():
    return os.listdir('webms/trash')


def get_held_webms(): return os.listdir('webms/good2')


def get_unheld_good_webms():
    return list(set(get_good_webms()) - set(get_held_webms()))


def get_stats():
    best = len(get_best_webms())
    return {
        'good': (len(get_good_webms()) - best),
        'bad': len(get_bad_webms()),
        'best': best,
        'pending': len(get_pending_webms()),
        'trash': len(get_trash_webms()),
        'total': len(get_all_webms())
    }


def delete_holding_queue():
    shutil.rmtree('webms/good2')
    os.makedirs('webms/good2')


@app.route('/<name>.webm', subdomain='<domain>')
@app.route('/<name>.webm')
def serve_webm(name, domain=None):
    if request.accept_mimetypes.best_match(['video/webm', 'text/html']) == 'text/html':
        return redirect(name)

    webm = get_video(name)
    if not webm:
        abort(404, 'Cannot find that webm!')
    #elif webm.reported:
    #    abort(403, 'webm was reported')

    address = Address.query.filter(Address.address == get_ip())[0]
    db.session.add(Action(address, webm, 'view'))
    db.session.commit()
    return send_from_directory('webms/all', name+".webm")


@app.route('/<name>', subdomain='<domain>')
@app.route('/<name>')
def show_webm(name, domain=None):
    name = name + '.webm'
    queue = 'pending'
    token = None
    if name not in get_all_webms():
        abort(404)
    elif name not in get_safe_webms():
        if name not in get_quality_webms():
            abort(403)
    if name in get_best_webms():
        queue = 'best'
    elif name in get_music_webms():
        queue = 'music'
    elif name in get_good_webms():
        queue = 'good'
    elif name in get_bad_webms():
        queue = 'bad'
        token = generate_webm_token(name)

    return render_template('display.html', webm=name, queue=queue, token=token, history=get_log(name))


@app.route('/')
def serve_random():
    try:
        pending = get_pending_webms()
        webm = choice(pending)
    except IndexError:
        pass
    return render_template('display.html', webm=webm.path, token=generate_webm_token(webm), count=len(pending), history=make_video_history(webm.id), stats=get_stats(), unpromotable=is_unpromotable(webm))

@app.route('/', subdomain='good')
def serve_good():
    global delta
    best = None
    held = 0
    try:
        good = get_unheld_good_webms()
        if len(good) == 0:
            delete_holding_queue()
            good = get_unheld_good_webms()
        else:
            held = len(get_held_webms())
        webm = choice(good)
        if webm in get_best_webms():
            best = True
    except IndexError:
        abort(404, 'You need to promote some webms!')
    return render_template('display.html', webm=webm, token=generate_webm_token(webm), queue='good', count=len(good), best=best, held=held, unpromotable=is_unpromotable(webm), stats=get_stats(), history=get_log(webm), debug=u'\u0394'+str(delta))

@app.route('/', subdomain='decent')
def serve_all_good():
    try:
        good = get_held_webms()
        webm = choice(good)
    except IndexError:
        abort(404, 'There are no held webms.')
    return render_template('display.html', webm=webm, queue='good', stats=get_stats(), history=get_log(webm))


@app.route('/', subdomain='best')
def serve_best():
    try:
        webm = choice(get_best_webms())
    except IndexError:
        abort(404, 'You need to feature some webms!')
    if get_user_censured(webm):
        return redirect('/', 302)
    token = generate_webm_token(webm)
    return render_template('display.html', webm=webm, queue='best', token=token, unpromotable=is_votable(webm))


@app.route('/', subdomain='top')
def serve_best_nocensor():
    try:
        webm = choice(get_best_webms())
    except IndexError:
        abort(404, 'There are no featured webms.')
    token = generate_webm_token(webm)
    return render_template('display.html', webm=webm, queue='best', token=token, history=get_log(webm), unpromotable=is_votable(webm))

@app.route('/', subdomain='music')
def serve_music():
    try:
        webms = get_music_webms()
        webm = choice(webms)
    except IndexError:
        abort(404, 'You need to shunt some videos!')
    token = generate_webm_token(webm)
    return render_template('display.html', webm=webm, queue='music', token=token, history=get_log(webm), count=len(webms))

@app.route('/', subdomain='index')
def serve_best_index():
    webms = get_best_webms()
    return render_template('index.html', webms=webms)


@app.route('/', subdomain='bad')
def serve_bad():
    try:
        webms = get_bad_webms()
        webm = choice(webms)
    except IndexError:
        abort(404, 'No webms have been marked bad.')
    return render_template('display.html', webm=webm, token=generate_webm_token(webm), queue='bad', count=len(webms), stats=get_stats())


def mark_ugly(webm):
    global delta;
    delta -= 5
    add_log(webm, 'reported')
    os.symlink('webms/all/' + webm, 'webms/trash/' + webm)


def mark_veto(webm):
    add_log(webm, 'vetoed')
    os.symlink('webms/all/' + webm, 'webms/veto/' + webm)


def mark_hold(webm):
    add_log(webm, 'held')
    os.symlink('webms/all/' + webm, 'webms/good2/' + webm)


def unmark_good(webm):
    global delta;
    delta -= 1
    add_log(webm, 'demoted')
    os.unlink('webms/good/' + webm)


def unmark_bad(webm):
    global delta;
    delta += 1
    add_log(webm, 'forgiven')
    os.unlink('webms/bad/' + webm)

def mark_music(webm):
    global delta
    delta += 3
    os.unlink('webms/good/' + webm)
    os.symlink('webms/all/' + webm, 'webms/music/' + webm)
    add_log(webm, 'shunted')

def unmark_music(webm):
    global delta
    delta -= 3
    os.unlink('webms/music/' + webm)
    os.symlink('webms/all/' + webm, 'webms/good/' + webm)
    add_log(webm, 'unshunted')

def mark_best(webm):
    global delta;
    delta += 5
    add_log(webm, 'featured ****')
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto('http://best.webm.website/' + webm + ' has been marked as "best" by ' + map_ips(get_ip(), get_ip()), (
        'saraneth.lon.fluv.net',
        41337
    ))
    os.symlink('webms/all/' + webm, 'webms/best/' + webm)


@app.route('/moderate', methods=['POST'])
@app.route('/moderate', methods=['POST'], subdomain='<domain>')
def moderate_webm(domain=None):
    name = request.form['webm']
    webm = get_video(name.replace(".webm", ""))
    token = request.form['token'].split(':')
    if not (token[0] + ':' + token[1] == generate_webm_token(webm, token[1])):
        abort(400, 'token mismatch')

    verdict = request.form['verdict']

    status = None
    try:
        if verdict == 'good':
            webm.score += 1
            #status = mark_good(webm)
        elif verdict == 'bad':
            #status = mark_bad(webm)
            webm.score -= 1
        else:
            abort(400, 'invalid verdict')
        """
        elif verdict == 'shunt':
            if webm in get_good_webms():
                status = mark_music(webm)
            else:
                abort(400, 'can only shunt good webms')
        elif verdict == 'unshunt':
            if webm in get_music_webms():
                status = unmark_music(webm)
            else:
                abort(400, 'can only unshunt if shunted!')
        elif verdict == 'report':
            status = mark_ugly(webm)
        elif verdict == 'demote':
            if webm in get_good_webms():
                unmark_good(webm)
                flash('Demoted ' + webm)
                return redirect('/', 303)
            else:
                abort(400, 'can only demote good webms')
        elif verdict == 'feature':
            if is_unpromotable(webm):
                abort(400, 'not allowed to feature')
            if webm in get_good_webms():
                mark_best(webm)
                flash('Promoted ' + webm)
                return redirect('/', 303)
            else:
                abort(400, 'can only feature good webms')
        elif verdict == 'forgive':
            if webm in get_bad_webms():
                unmark_bad(webm)
                flash('Forgave ' + webm)
                return redirect('/', 303)
            else:
                abort(400, 'can only forgive bad webms')
        elif verdict == 'keep' or verdict == 'hold':
            if webm in get_unheld_good_webms():
                mark_hold(webm)
            return redirect('/')
        elif verdict == 'veto' or verdict == 'nsfw':
            if webm in get_good_webms():
                if webm not in get_best_webms():
                    mark_veto(webm)
                    return redirect('/', 303)
                else:
                    abort(400, 'cannot veto things already in best')
            else:
                abort(400, 'can only veto good webms')
        elif verdict == 'unsure':
            # placebo
            add_log(webm, 'skipped')
            return redirect('/')
        elif verdict == 'affirm' or verdict == 'censure':
            if not is_votable(webm):
                if webm in get_best_webms():
                    add_log(webm, verdict)
            else:
                abort(400, is_votable(webm))
        """

        flash('Marked ' + webm.name + ' as ' + verdict)

        address = Address.query.filter(Address.address == get_ip())[0]
        db.session.add(Action(address, webm, verdict))
        db.session.commit()
        return redirect('/', '303')
    except OSError:  # file exists
        flash('Unable to mark ' + webm + ' as ' + verdict)
    return redirect('/')


if __name__ == '__main__':

    required_dirs = [
        'webms',
        'webms/good',
        'webms/bad',
        'webms/trash',
        'webms/best',
        'webms/good2',
        'webms/metadata',
        'webms/veto',
        'webms/music'
    ]
    for directory in required_dirs:
        if not os.path.exists(directory):
            os.makedirs(directory)

    app.config.update(
        SECRET_KEY=SETTINGS.SECRET_KEY,
        SERVER_NAME=SETTINGS.SERVER_NAME
    )

    if SETTINGS.DEBUG:
        app.debug = True
        log = None
    else:
        log = logging.getLogger('werkzeug')
        log.setLevel(logging.WARNING)

    app.run(host='0.0.0.0', port=3000)
