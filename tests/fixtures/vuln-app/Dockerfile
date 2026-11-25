FROM node
ENV STRIPE_SECRET=sk_test_dummy_value_123
COPY . /app
RUN curl -fsSL https://example.com/install.sh | sh
CMD ["node", "/app/src/server.js"]
