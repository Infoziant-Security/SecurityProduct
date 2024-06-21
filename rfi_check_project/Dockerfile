# Use an official Python runtime as a parent image
FROM python:3.9

# Set the working directory
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install netcat-openbsd and other necessary tools
RUN apt-get update && apt-get install -y netcat-openbsd

# Run rfi_to_rce_check.py when the container launches
ENTRYPOINT ["python", "rfi_to_rce_check.py"]
