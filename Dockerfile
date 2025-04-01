FROM python:3.9-slim

WORKDIR /app

# Install system dependencies required for mysqlclient and other packages
RUN apt-get update && apt-get install -y \
    default-libmysqlclient-dev \
    pkg-config \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create upload directories
RUN mkdir -p appstarcatcher/static/uploads/{image_player,packs,clubs,clubs/bannerclub}

# Set permissions for upload directories
RUN chmod -R 777 appstarcatcher/static/uploads

# Environment variables
ENV FLASK_APP=appstarcatcher
ENV FLASK_ENV=production
ENV MYSQL_DATABASE=starcatcher
ENV MYSQL_USER=starcatcher
ENV MYSQL_PASSWORD=starcatcher123
ENV MYSQL_HOST=db

# Run gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "appstarcatcher:app"]
