# Use a lightweight Python base image
FROM python:3.10-slim

# Set the working directory for the application
WORKDIR /app

# Copy and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the API server script
COPY api.py .

# Expose the port the application runs on (Port 8000)
EXPOSE 8000

# Command to run the application using Gunicorn (Production Mode)
# Binds Gunicorn to 0.0.0.0:8000 inside the container
#CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "4", "api:app"]
CMD ["python3", "api.py", "-v"]
