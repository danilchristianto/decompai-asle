# Use the official GCC image
# FROM gcc_linux_x86_64:latest
FROM radare/radare2:latest AS base

# Switch to root user
USER root

# Install necessary dependencies including radare2 and gcc
RUN apt-get update && \
    apt-get -y install gcc mono-mcs gdb && \
    rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get -y install gdbserver && \
    rm -rf /var/lib/apt/lists/*

# libc6:i386
RUN apt-get update && apt-get -y install libc6-dev-i386

RUN apt-get install -y gdb-multiarch qemu-user-static qemu-user

# Install python
RUN apt-get update && apt-get -y install python3 python3-pip

# Alias python to python3
RUN ln -s /usr/bin/python3 /usr/bin/python

# Install file
RUN apt-get update && apt-get install -y file binutils-mips-linux-gnu && rm -rf /var/lib/apt/lists/*

# Install Java (required for Ghidra)
RUN apt-get update && apt-get install -y openjdk-21-jdk wget unzip && \
rm -rf /var/lib/apt/lists/*

# Set environment variables for Ghidra
ENV GHIDRA_VERSION=11.3.1
ENV GHIDRA_HOME=/opt/ghidra
ENV GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.3.1_build/ghidra_11.3.1_PUBLIC_20250219.zip

# Download and install Ghidra
RUN wget -O /tmp/ghidra.zip $GHIDRA_URL && \
    unzip /tmp/ghidra.zip -d /opt && \
    rm /tmp/ghidra.zip && \
    mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC $GHIDRA_HOME

# Add Ghidra to PATH
ENV PATH="$GHIDRA_HOME:$GHIDRA_HOME/support:$PATH"

USER r2

WORKDIR /

# Command to keep the container alive (if needed)
CMD ["bash"]