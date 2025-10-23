
# Use official Python image
FROM python:3.12-slim

# Set working directory inside container
WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Set environment variable for Flask (optional)
ENV FLASK_ENV=production

# Command to run your app
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8080"]
