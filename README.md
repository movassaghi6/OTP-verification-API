instructions:
   1.create a virtual environment in project's folder with:
     - python -m venv venv
   2.activate virtual environment with:
     - venv/Scripts/activate
   3.install requirements with:
     - pip install -r requirements.txt
   4.run migration commands with:
     1- python manage.py makemigrations accounts
     2- python manage.py migrate
   5.run server with this command:
     - python manage.py runserver
