import os
from dotenv import load_dotenv
from app import create_app

load_dotenv()  # Cargar variables de entorno desde el archivo .env

app = create_app()

if __name__ == "__main__":
    app.run('localhost', 5000, debug=True)
