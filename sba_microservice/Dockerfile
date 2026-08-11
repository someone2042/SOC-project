FROM python:3.10-slim

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the microservice source code
# We assume the models directory has already been populated by train.py on the host
COPY . /app

# Run the scheduler
CMD ["python", "run_scheduler.py"]
