FROM python:3.9-slim

WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Create templates directory if it doesn't exist
RUN mkdir -p templates

# Expose the port the app runs on
EXPOSE 8080

# Command to run the application
CMD ["python", "github_secret_detector.py"] 