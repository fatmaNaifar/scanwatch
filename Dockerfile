# Use an official Ubuntu as a parent image
FROM ubuntu:20.04

# Set environment variables to non-interactive for non-interactive apt-get installs
ENV DEBIAN_FRONTEND=noninteractive

# Install necessary packages and RethinkDB
RUN apt-get update && \
    apt-get install -y wget gnupg && \
    echo "deb https://download.rethinkdb.com/apt focal main" | tee /etc/apt/sources.list.d/rethinkdb.list && \
    wget -qO- https://download.rethinkdb.com/apt/pubkey.gpg | apt-key add - && \
    apt-get update && \
    apt-get install -y rethinkdb && \
    apt-get clean

# Expose RethinkDB ports
EXPOSE 28015
EXPOSE 8080

# Command to run RethinkDB
CMD ["rethinkdb", "--bind", "all"]
