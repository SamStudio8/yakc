import app
import os

app.db.create_all()

lh = app.User("system")
app.db.session.add(lh)

ip = app.Address("127.0.0.1", lh)
app.db.session.add(ip)
app.db.session.commit()

for f in os.listdir('webms/all'):
    video = app.Video(f, f.replace(".webm", ""))
    app.db.session.add(video)
    app.db.session.commit()
    app.db.session.add(app.Action(ip, video, "upload"))
    app.db.session.commit()


