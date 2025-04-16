# Starcatcher Web Application

A web application built with Flask.

## Prerequisites

- Python 3.x
- PostgreSQL

## Setup

1. Clone the repository:
```bash
git clone https://github.com/Mohammed-hani69/Starcatcher.git
cd StarcatcherWeb
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your configuration:
```
DATABASE_URL=postgresql://username:password@localhost:5432/dbname
FLASK_APP=app.py
FLASK_ENV=development
```

5. Initialize the database:
```bash
flask db upgrade
```

6. Run the application:
```bash
flask run
```

## Dependencies

- Flask: Web framework
- Flask-SQLAlchemy: Database ORM
- Flask-Migrate: Database migrations
- Flask-CORS: Cross-Origin Resource Sharing
- PostgreSQL: Database
- Gunicorn: Production WSGI server
- Python-dotenv: Environment variable management

## Development

To contribute to this project:

1. Configure Git line endings (recommended):
```bash
git config --global core.autocrlf false
```

2. Initialize Git and setup remote:
```bash
git init
git branch -M main
git remote add origin https://github.com/Mohammed-hani69/Starcatcher.git
```

3. Initial push to repository:
```bash
git add .
git commit -m "Initial commit"
git push -f origin main
```

4. For future changes:
```bash
git add .
git commit -m "update to v 2.2.10"
git push origin main
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
