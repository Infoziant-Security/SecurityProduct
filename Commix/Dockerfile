# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Install dependencies
RUN apt-get update && apt-get install -y git

# Clone the commix repository
RUN git clone https://github.com/commixproject/commix.git /app/commix

# Set the working directory to the commix directory
WORKDIR /app/commix

# Run commix
ENTRYPOINT ["python3", "commix.py"]
