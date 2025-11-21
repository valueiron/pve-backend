# Use a small Python base image
FROM python:3.12-alpine

# Set working directory
WORKDIR /app

# Copy dependency list and install only what's needed
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Flask app
COPY . .

# Expose Flask's default port
EXPOSE 5000

# Run the app
CMD ["python", "app.py"]
