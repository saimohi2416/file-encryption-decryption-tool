# SecureVault — Sharing & Deployment Guide

SecureVault runs **100% in the web browser** using the Web Crypto API (`window.crypto.subtle`).
To protect users, **modern web browsers only enable cryptographic APIs in Secure Contexts** (i.e. `https://` URLs, `localhost`, or `127.0.0.1`).

If you share a standard HTTP link over your local network (like `http://192.168.1.100:8000`), other users will experience errors unless you follow the steps below.

Here are the best ways to share SecureVault with others:

---

## Option 1: Zero-Config Deployment on Netlify Drop (Easiest & Fastest)
You can deploy SecureVault to a public, secure `https://` URL in 10 seconds without running any commands or creating a GitHub repository.

1. Open your web browser and go to [Netlify Drop](https://app.netlify.com/drop).
2. Drag and drop your **file encryption tool** project folder onto the page.
3. Netlify will instantly upload the static files and generate a secure public URL (e.g., `https://your-app-name.netlify.app`).
4. Share this URL with your colleagues. The app will work perfectly with zero errors since it is hosted on HTTPS!

---

## Option 2: Deploy to GitHub Pages (Free & Persistent)
If your code is in a GitHub repository:

1. Push your code to your GitHub repository.
2. In your repository on GitHub, click on **Settings** (top tab).
3. On the left sidebar, click **Pages**.
4. Under **Build and deployment**, select:
   * **Source**: *Deploy from a branch*
   * **Branch**: *main* (or *master*) and folder */ (root)*.
5. Click **Save**.
6. Wait 1-2 minutes. GitHub will publish your site to a secure URL: `https://<your-username>.github.io/<your-repository-name>`.

---

## Option 3: Deploy to Vercel (Professional & Automated)
If you have a Vercel account:

1. Install Vercel CLI globally or run it via npx:
   ```bash
   npx vercel
   ```
2. Follow the login prompts and link the project.
3. Vercel will deploy the static site in seconds and provide a secure URL (e.g., `https://securevault.vercel.app`).

---

## Option 4: Share via a Secure Tunnel (ngrok)
If you want to run the server on your local machine but share it over the internet securely via HTTPS:

1. Install `ngrok` (download from [ngrok.com](https://ngrok.com)).
2. Start your local server:
   ```bash
   python securevault.py serve --port 8000
   ```
3. In a separate terminal, start the secure tunnel:
   ```bash
   ngrok http 8000
   ```
4. ngrok will generate a secure HTTPS forwarding address (e.g., `https://a1b2-34-56-78.ngrok-free.app`).
5. Share this HTTPS link. It tunnels traffic to your computer securely, and the browser will enable Web Crypto!

---

## Option 5: Local Network (Wi-Fi/LAN) Sharing
If you want to share the app directly using your local IP address (e.g. `http://192.168.x.x:8000`) without deploying online:

1. Run the server:
   ```bash
   python securevault.py serve
   ```
2. Note the **Network Address** shown in the terminal console (e.g., `http://192.168.1.50:8000`).
3. Share this URL with the other person on your network.
4. **Important**: When they open the URL, their browser will show the **Insecure Context Blocked** banner. To bypass this for testing:
   * Open Chrome or Edge on their system.
   * Go to the URL: `chrome://flags/#unsafely-treat-insecure-origin-as-secure`
   * Paste your URL `http://192.168.1.50:8000` into the text box.
   * Set the dropdown option next to it to **Enabled**.
   * Click **Relaunch** (or restart the browser).
   * Reload your page. The warning will disappear, and the cryptographic functions will work perfectly!
