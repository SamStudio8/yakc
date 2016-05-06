from flask import (Flask, send_from_directory, abort,
                  render_template, request, flash, redirect)
from flask_sqlalchemy import SQLAlchemy
from random import choice, random, randint
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

try:
    import raven
    from raven.contrib.flask import Sentry
except ImportError:
    pass
else:
    release = raven.fetch_git_sha(os.path.dirname(__file__))
    client = raven.Client(release=release)
    sentry = Sentry(app, client=client)

if SETTINGS.PERF_LOG:
    #http://docs.sqlalchemy.org/en/rel_1_0/faq/performance.html
    from sqlalchemy import event
    from sqlalchemy.engine import Engine
    import time
    import logging

    logging.basicConfig()
    logger = logging.getLogger("myapp.sqltime")
    logger.setLevel(logging.DEBUG)

    @event.listens_for(Engine, "before_cursor_execute")
    def before_cursor_execute(conn, cursor, statement,
            parameters, context, executemany):
        conn.info.setdefault('query_start_time', []).append(time.time())
        logger.debug("%s\tStart Query: %s" % (datetime.now().strftime("%H:%M:%S.%f"), statement))

    @event.listens_for(Engine, "after_cursor_execute")
    def after_cursor_execute(conn, cursor, statement,
            parameters, context, executemany):
        total = time.time() - conn.info['query_start_time'].pop(-1)
        logger.debug("%s\tQuery Complete!" % datetime.now().strftime("%H:%M:%S.%f"))
        logger.debug("%s\tTotal Time: %f" % (datetime.now().strftime("%H:%M:%S.%f"), total))

# NOTE
# Always append *new* actions to the end of VALID_ACTIONS
#   The list is used as a crap enum and thus the position
#   of each element in the list refers to the integer
#   used to store that action in the actual database.
#   Arbitrarily inserting actions will damage integrity
#   and cause future videos to be marked with different
#   numbering schemes which would probably be ungood.
VALID_ACTIONS = [
    "upload",
    "view",
    "good",
    "bad",
    "held",
    "feature",
    "demote",
    "skip",
    "shunt",
]

# List of VALID_ACTIONS that should be caught in the last_action
# field of the Video ORM class. These actions permit filtering.
IMPORTANT_ACTIONS = [
    "upload",
    "good",
    "bad",
    "held",
    "feature",
    "demote",
]

QUEUES = [
    "master",
    "music"
]

class Video(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    path = db.Column(db.String(255))
    name = db.Column(db.String(255), unique=True)
    nsfw = db.Column(db.Boolean)
    last_action = db.Column(db.Integer)
    queue = db.Column(db.Integer)

    def __init__(self, path, name, queue=0, last_action="upload", nsfw=False):
        self.path = path
        self.name = name
        self.queue = 0
        self.last_action = VALID_ACTIONS.index(last_action)
        self.nsfw = False

    def __repr__(self):
        return '<Video %r>' % (self.name)

    def get_history(self):
        return self.actions.all()

    def get_last_important_action_type(self):
        try:
            return self.actions.filter(Action.important == True).order_by("timestamp desc")[0].action
        except IndexError:
            return None

def get_videos_of_status(action_type, queue="master"):
    return Video.query.filter(Video.queue == QUEUES.index(queue), Video.last_action == VALID_ACTIONS.index(action_type))

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
    action = db.Column(db.Integer) # Should probably be an FK...
    timestamp = db.Column(db.DateTime)
    important = db.Column(db.Boolean)

    note = db.Column(db.String(64))

    address = db.relationship('Address', backref=db.backref('actions', lazy='dynamic'))
    video = db.relationship('Video', backref=db.backref('actions', lazy='dynamic'), lazy="joined")

    def __init__(self, address, video, action, note="", important=False):
        self.address_id = address.id
        self.video_id = video.id
        self.action = action
        self.timestamp = datetime.utcnow()
        self.note = note

        if action in IMPORTANT_ACTIONS:
            important = True
        self.important = important

    def __repr__(self):
        stamp = self.timestamp.strftime('%Y-%m-%d %H:%M:%S')
        if self.address.user:
            un = self.address.user.username
        else:
            un = self.address.address

        if self.note:
            return "%s - %s (%s) by %s" % (stamp, self.action, self.note, un)
        else:
            return "%s - %s by %s" % (stamp, self.action, un)

delta = 0

def map_ips(ip, default):
    with open('addresses.json') as fp:
        addrs = json.load(fp)
        return addrs.get(ip, default)

def md5_to_file(md5):
    with open('webms/md5.txt', 'r') as fp:
        strings = fp.read()
        fp.close()
    if strings is not None:
        strings = strings.split('\n')
        for string in strings:
            string = string.split('  ')
            if md5 == string[0]:
                return string[1].split('/')[1]
    return False


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
    #log = get_log(webm)
    log = None
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

    if "feature" in actions:
        return 'already featured'
    elif "good" in actions:
        return 'cannot feature own videos'
    elif "bad" in actions:
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


def generate_webm_token(webm, salt=None):
    if not salt:
        salt = uuid4().hex
    return sha256(app.secret_key.encode() + webm.encode() + salt).hexdigest()+ ':' + salt

#TODO(samstudio8) 404 on failure
def get_video(name):
    try:
        return Video.query.filter(Video.name == name)[0]
    except IndexError:
        return None

def get_address(address):
    try:
        return Address.query.filter(Address.address == address)[0]
    except IndexError:
        # A new IP, how exciting (!)
        #TODO(samstudio8) This is probably noteworthy of logging
        new_address = Address(address)
        db.session.add(new_address)
        db.session.commit()
        return new_address

def get_address_video_actions(raw_ip, webm_id):
    address = get_address(raw_ip)
    if address.user:
        actions = [x[0] for x in Action.query.filter(Action.address_id.in_( address.user.addresses.with_entities(Address.id) ), Action.video_id == webm_id).with_entities(Action.action).all()]
    else:
        actions = [x[0] for x in Action.query.filter(Action.address_id == address.address, Action.video_id == webm_id).with_entities(Action.action).all()]
    return actions


def get_stats():
    best = get_videos_of_status("best").count()
    return {
        'good': (get_videos_of_status("good") - best),
        'bad': get_videos_of_status("bad").count(),
        'music': get_videos_of_status("good", queue="music").count(),
        'held': get_videos_of_status("held").count(),
        'best': best,
        'pending': get_videos_of_status("upload").count(),
        'total': Video.query.count(),
    }

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

    address = get_address(get_ip())
    db.session.add(Action(address, webm, 'view'))
    db.session.commit()
    return send_from_directory('webms/all', webm.path)


@app.route('/<name>', subdomain='<domain>')
@app.route('/<name>')
def show_webm(name, domain=None):
    webm = get_video(name)
    if not webm:
        abort(404, 'Cannot find that webm!')

    queue = webm.get_last_important_action_type()
    #TODO Check nsfw/quality

    return render_template('display.html', webm=webm, queue=queue, token=generate_webm_token(webm))

@app.route('/md5/<md5>')
def serve_md5(md5):
    webm = md5_to_file(md5)
    if webm:
        return redirect(webm)
    else:
        abort(404, 'md5 match not found')

@app.route('/')
def serve_random():
    pending = get_videos_of_status("upload")
    c = pending.count()
    if c == 0:
        abort(404, "No pending videos!")
    webm = pending[randint(0, c-1)]
    return render_template('display.html', webm=webm, token=generate_webm_token(webm), count=c, unpromotable=is_unpromotable(webm))

@app.route('/', subdomain='decent')
def serve_good():
    global delta

    good = get_videos_of_status("good")
    gc = good.count()
    held = get_videos_of_status("held")
    hc = held.count()
    if gc == 0:
        #TODO(samstudio8) Bump everything back to good in a less crap way?
        for video in held:
            address = get_address("127.0.0.1")
            db.session.add(Action(get_address("127.0.0.1"), video, 'good'))
        db.session.commit()
        good = held

    if gc == 0:
        abort(404, 'You need to promote some webms!')

    webm = good[randint(0, gc-1)]

    #if webm in get_best_webms():
    #    best = True
    best=False
    return render_template('display.html', webm=webm, token=generate_webm_token(webm), queue='good', count=gc, best=best, held=hc, unpromotable=is_unpromotable(webm), debug=u'\u0394'+str(delta))

"""
@app.route('/', subdomain='new.decent')
def serve_unjudged_good():
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
        if webm in get_videos_of_status("feature"):
            best = True
    except IndexError:
        abort(404, 'You need to promote some webms!')
    unpromotable = is_unpromotable(webm)
    if unpromotable:
        return redirect('/')
    else:
        return render_template('display.html', webm=webm, token=generate_webm_token(webm), queue='good', count=len(good), best=best, held=held, unpromotable=is_unpromotable(webm), stats=get_stats(), history=get_log(webm), debug=u'\u0394'+str(delta))
"""

@app.route('/', subdomain='good')
def redirect_to_held():
    return redirect('//held.' + app.config['SERVER_NAME'])

@app.route('/', subdomain='held')
def serve_held():
    try:
        good = get_videos_of_status("held")
        webm = choice(good)
    except IndexError:
        abort(404, 'There are no held webms.')

    webm = held[randint(0, c-1)]
    return render_template('display.html', webm=webm, queue='good', stats=get_stats())


@app.route('/', subdomain='best')
def serve_best():
    best = get_videos_of_status("feature")
    c = best.count()
    if c == 0:
        abort(404, 'You need to feature some webms!')

    webm = best[randint(0, c-1)]

    #if get_user_censured(webm):
    #    return redirect('/', 302)
    return render_template('display.html', webm=webm, queue='best', token=generate_webm_token(webm), unpromotable=is_votable(webm))


@app.route('/', subdomain='top')
def serve_best_nocensor():
    try:
        webm = choice(get_videos_of_status("feature"))
    except IndexError:
        abort(404, 'There are no featured webms.')
    token = generate_webm_token(webm)
    return render_template('display.html', webm=webm, queue='best', token=token, unpromotable=is_votable(webm))

@app.route('/', subdomain='music')
def serve_music():
    videos = get_videos_of_status("good", queue="music")
    c = videos.count()
    if c == 0:
        abort(404, 'You need to identify some musical webms!')

    webm = videos[randint(0, c-1)]
    return render_template('display.html', webm=webm, queue='music', token=generate_webm_token(webm), count=c)

@app.route('/', subdomain='index')
def serve_best_index():
    webms = get_videos_of_status("feature")
    return render_template('index.html', webms=webms)


@app.route('/', subdomain='bad')
def serve_bad():
    videos = get_videos_of_status("bad")
    c = videos.count()
    if c == 0:
        abort(404, 'You need to dislike some webms!')

    webm = videos[randint(0, c-1)]
    return render_template('display.html', webm=webm, token=generate_webm_token(webm), queue='bad', count=c, stats=get_stats())


def mark_ugly(webm):
    global delta;
    delta -= 5
    add_log(webm, 'reported')
    os.symlink('webms/all/' + webm, 'webms/trash/' + webm)


def mark_veto(webm):
    add_log(webm, 'vetoed')
    os.symlink('webms/all/' + webm, 'webms/veto/' + webm)


@app.route('/moderate', methods=['POST'])
@app.route('/moderate', methods=['POST'], subdomain='<domain>')
def moderate_webm(domain=None):
    name = request.form['webm']
    webm = get_video(name.replace(".webm", ""))
    token = request.form['token'].split(':')
    if not (token[0] + ':' + token[1] == generate_webm_token(webm, token[1])):
        abort(400, 'token mismatch')

    verdict = request.form['verdict']

    address = get_address(get_ip())
    un = address.address
    if address.user:
        un = address.user.username

    # Translate verdicts if necessary
    if verdict == "unsure":
        verdict = "skip"
    elif verdict == "keep":
        verdict = "hold"

    if verdict not in VALID_ACTIONS:
        abort(400, 'invalid verdict')

    # Check verdict integrity
    #TODO(samstudio8) Should probably check the user is actually permitted
    if verdict == 'feature':
        if is_unpromotable(webm):
            abort(400, 'not allowed to feature')
        if webm.get_last_important_action_type() != "good":
            abort(400, 'can only feature good webms')

        if SETTINGS.NOTIFY_SERVER_NAME:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.sendto('http://best.' + SETTINGS.SERVER_NAME + '/' + webm.name + ' has been marked as "best" by ' + un, (
                SETTINGS.NOTIFY_SERVER_NAME,
                SETTINGS.NOTIFY_SERVER_PORT
            ))
    elif verdict == 'music':
        if webm.get_last_important_action_type() != "good":
            abort(400, 'can only shunt good webms')
    elif verdict == "demote":
        if webm.get_last_important_action_type() != "good":
            abort(400, 'can only demote good webms')
    """
    elif verdict == 'unshunt':
        if webm in get_music_webms():
            status = unmark_music(webm)
        else:
            abort(400, 'can only unshunt if shunted!')
    elif verdict == 'report':
        status = mark_ugly(webm)
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
    elif verdict == 'affirm' or verdict == 'censure':
        if not is_votable(webm):
            if webm in get_best_webms():
                add_log(webm, verdict)
        else:
            abort(400, is_votable(webm))
    """

    flash('Marked ' + webm.name + ' as ' + verdict)

    note = ""
    if verdict == "shunt":
        new_queue = request.form['shunt']
        shunt_webm(webm, new_queue)
        note = "to %s" % new_queue
    record_verdict(webm, verdict, note)

    return redirect('/', '303')
    return redirect('/')

def record_verdict(webm, verdict, note=""):
    if verdict not in ["unsure"]:
        if verdict in IMPORTANT_ACTIONS:
            webm.last_action = VALID_ACTIONS.index(verdict)
        address = Address.query.filter(Address.address == get_ip())[0]
        db.session.add(Action(address, webm, verdict, note))
        db.session.commit()

def shunt_webm(webm, new_queue):
    if new_queue not in QUEUES:
        abort(403, 'invalid queue')
    webm.queue = QUEUES.index(new_queue)
    db.session.commit()

if __name__ == '__main__':

    required_dirs = [
        'webms',
        'webms/all',
        'webms/bad',
        'webms/best',
        'webms/good',
        'webms/held',
        'webms/metadata',
        'webms/music'
        'webms/trash',
        'webms/veto',
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

    app.run(host='0.0.0.0', port=SETTINGS.SERVER_PORT)
