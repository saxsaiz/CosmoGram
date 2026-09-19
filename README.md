# Lime GRAM Telegram WebApp — Render

## Deploy
1. Upload these files to a PRIVATE GitHub repository:
   - app.py
   - requirements.txt
   - render.yaml
   - templates/index.html

2. In Render choose **New → Blueprint** and select the repository.
   Render will read `render.yaml`.

3. Set the environment variables:
   - `BOT_TOKEN` — the same bot token used by Lime GRAM.
   - `IP_HASH_SALT` — a long random secret string. Keep it unchanged after deployment.
   - `BOT_DB_PATH` — path to the SAME SQLite database used by the bot.

4. After deployment, copy the HTTPS URL, for example:
   `https://limegram-webapp.onrender.com/`

5. Put that URL in the bot:
   `WEBAPP_URL = "https://limegram-webapp.onrender.com/"`

## Important: SQLite
The WebApp must access the same database as the bot. A separate Render filesystem/database will NOT automatically be the bot's database.

If your bot is running on another PC/hosting service, `BOT_DB_PATH=tenx_gram.db` on Render points to a different file. In that case IP records will not reach the bot.

For a shared SQLite database, the bot and WebApp need to run on the same persistent filesystem/server. For production, a shared database such as PostgreSQL is a better architecture.

## Security
- Keep the GitHub repository private.
- Never put `BOT_TOKEN` in source code or commit it.
- Do not change `IP_HASH_SALT` after users have been recorded, otherwise old IP hashes will no longer match.
- IP matching is not proof that two accounts belong to one person: family/shared Wi-Fi, school networks, mobile carrier NAT and VPNs can cause the same public IP to be shared.
