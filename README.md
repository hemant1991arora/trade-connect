# TradeConnect – B2B supplier marketplace

Buyers (no login) search products and suppliers, filter by city and category, and send enquiries.
Suppliers register themselves, list products with photos, and manage enquiries in a dashboard.
The admin approves/verifies suppliers and can bulk-import suppliers from Excel, CSV, JSON or an image.
When a supplier registers (or you import them), the site searches the internet with Claude and
pre-fills owner, website, address, about and brands. Suppliers review and edit the result.

## Deploy on Render
1. Put this folder in a GitHub repo.
2. Render.com -> New -> Web Service -> choose the repo. Build: `npm install`   Start: `npm start`
3. Environment variables (see `.env.example`): ANTHROPIC_API_KEY, SESSION_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, AUTO_APPROVE.
4. Add a Disk (paid plan) mounted at `/data` and set `DATA_DIR=/data`. Without it, all data and photos are lost on restart.
5. Open the site and sign in with the admin email, then use the Admin page.

## Run locally
    npm install
    export $(grep -v '^#' .env | xargs) && npm start     # http://localhost:3000

## Good to know
- AUTO_APPROVE=false (default): new suppliers appear in search only after you approve them. Recommended against spam.
- Buyer name and phone are shown only to the supplier they enquire with. Supplier phone shows on the supplier page.
- Internet lookups use your Anthropic credits. Auto-filled values list their sources and low-confidence results are flagged.
- Not included yet: email/SMS alerts to suppliers, online payments, ratings and reviews.
