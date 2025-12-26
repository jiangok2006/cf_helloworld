# Hello World App

This project is a simple web application that displays "Hello World" using Cloudflare Pages for the UI and a Cloudflare Worker to handle requests.

## Project Structure

```
hello-world-app
├── public
│   └── index.html
├── worker
│   ├── index.js
│   └── wrangler.toml
├── package.json
└── README.md
```

## Setup Instructions

1. **Clone the repository**:
   ```
   git clone <repository-url>
   cd hello-world-app
   ```

2. **Install dependencies**:
   ```
   npm install
   ```

3. **Deploy the Cloudflare Worker**:
   Wrangler v3 replaced the old `publish` command with `deploy`. You can run Wrangler without installing it globally using `npx` or `npm exec`.
   From the project root run:
   ```bash
   cd worker
   npx wrangler deploy
   ```

   To run the worker locally during development:
   ```bash
   npx wrangler dev
   ```

   Optional: add a script to `package.json` and run via npm:
   ```json
   "scripts": {
     "deploy:worker": "wrangler deploy"
   }
   ```
   Then run:
   ```bash
   npm run deploy:worker --prefix .
   ```

4. **Run the application**:
   You can open `public/index.html` in your browser to see the "Hello World" message.

## Usage

- The web application will display "Hello World" when accessed.
- The Cloudflare Worker will respond with "Hello World" to any incoming requests.

## License

This project is licensed under the MIT License.