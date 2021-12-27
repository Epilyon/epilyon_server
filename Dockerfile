FROM rust:1.46-slim-buster as BUILDER

LABEL maintainer="Adrien Navratil <adrien1975@live.fr>"

# Setting up build project files
ENV BUILD_ROOT /tmp/epilyon-build
WORKDIR $BUILD_ROOT

# Installing openssl headers and pkg-config (required openssl-sys and backtrace-sys crates)
RUN apt-get -q update && apt-get install -y libssl-dev pkg-config

# Caching dependencies
COPY Cargo.toml .
COPY Cargo.lock .
RUN mkdir src \
    && echo "// dummy file" > src/lib.rs \
    && cargo build

COPY src src/

# Building
RUN cargo build


# Reseting the image build with clean Distroless image
FROM gcr.io/distroless/cc

# Copying files from BUILDER step
COPY --from=BUILDER /tmp/epilyon-build/target/debug/epilyon_server ./

# Final settings
EXPOSE 7899
CMD ["./epilyon_server"]