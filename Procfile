web: gunicorn app:app --config gunicorn.conf.py
release: python -c "from securecloud import create_app; from securecloud.extensions import db; app=create_app('production'); app.app_context().push(); db.create_all(); print('DB ready')"
