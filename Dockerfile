# Use the official GCC image
# FROM gcc_linux_x86_64:latest
FROM radare/radare2:latest


# Switch to root user
USER root

# Install necessary dependencies including radare2 and gcc
RUN apt-get update && \
    apt-get -y install gcc mono-mcs && \
    rm -rf /var/lib/apt/lists/*

USER r2

WORKDIR /

# Command to keep the container alive (if needed)
CMD ["bash"]