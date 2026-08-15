FROM rust:1-bookworm AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN useradd -r -u 10001 supply
COPY --from=build /app/target/release/supply-core /usr/local/bin/supply
USER supply
EXPOSE 4873
ENTRYPOINT ["supply"]
CMD ["serve", "--addr", "0.0.0.0:4873"]
