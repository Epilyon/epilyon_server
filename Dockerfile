FROM rust:1.46-alpine3.12 as BUILDER

LABEL maintainer="Adrien Navratil <adrien1975@live.fr>"

# Setting up build project files
ENV BUILD_ROOT /tmp/epilyon-build
WORKDIR $BUILD_ROOT

COPY src src/
COPY Cargo.toml .
COPY Cargo.lock .

# Building
RUN cargo build


# Reseting the image build with clean Alpine
FROM alpine:3.12

ENV USER epilyon
ENV EPILYON_ROOT /var/run/epilyon

# Creating the runner user
RUN addgroup -g 1000 $USER && adduser -u 1000 -D -G $USER $USER

# Setting up runtime project files
RUN mkdir -p $LINK_ROOT
WORKDIR $LINK_ROOT

RUN chown $USER:$USER $LINK_ROOT

USER $USER

# Copying files from BUILDER step
COPY --from=BUILDER /tmp/epilyon-build/epilyon_server ./

# Final settings
EXPOSE 7899
CMD ["./epilyon_server"]