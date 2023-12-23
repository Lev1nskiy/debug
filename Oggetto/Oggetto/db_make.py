from Oggetto import db, site
with site.app_context():
    db.create_all()