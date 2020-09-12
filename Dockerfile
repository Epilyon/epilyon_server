FROM rust:1.46-slim-buster as BUILDER

LABEL maintainer="Adrien Navratil <adrien1975@live.fr>"

# Setting up build project files
ENV BUILD_ROOT /tmp/epilyon-build
WORKDIR $BUILD_ROOT

# Installing openssl headers and pkg-config (required openssl-sys and backtrace-sys crates)
RUN apt install openssl pkg-config

COPY src src/
COPY Cargo.toml .
COPY Cargo.lock .

# Building
RUN cargo build


# Reseting the image build with clean Debian
FROM debian:buster-slim

ENV USER epilyon
ENV EPILYON_ROOT /var/run/epilyon

# Installing openssl (required by openssl crate)
RUN apt install openssl

# Creating the runner user
RUN addgroup --gid 1000 $USER && adduser -u 1000 --group $USER --system

# Setting up runtime project files
RUN mkdir -p $EPILYON_ROOT
WORKDIR $EPILYON_ROOT

RUN chown $USER:$USER $EPILYON_ROOT

USER $USER

# Copying files from BUILDER step
COPY --from=BUILDER /tmp/epilyon-build/target/debug/epilyon_server ./

# Final settings
EXPOSE 7899
CMD ["./epilyon_server"]