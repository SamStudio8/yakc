import app
import os

app.db.create_all()

lh = app.User("localhost")
app.db.session.add(lh)

for f in os.listdir('webms/all'):
    for i in range(0,12000):
        toot = ""
        if i > 0:
            toot = str(i)
        video = app.Video(f, f.replace(".webm", "")+toot)
        app.db.session.add(video)
app.db.session.commit()

ip = app.Address("127.0.0.1", lh)
app.db.session.add(ip)
app.db.session.commit()

