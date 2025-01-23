# SSL Checker Bot

## Description:
This is a Telegram bot for checking SSL certificates and retrieving domain information.  
The bot analyzes the SSL certificates of a provided website, displays detailed information,  
generates a chart of expiration dates, and provides WHOIS data.

---

## Features:
### SSL Certificate Check:
- Details of certificates (CN, Issuer, validity period).
- Expiration status.
- Days remaining until expiration.

### Chart Generation:
- A themed bar chart showing SSL expiration timelines.

### WHOIS Information:
- Registrar.
- Registration date.
- Expiration date.

---

## Technologies Used:
- **Node.js**.  
- **Telegram Bot API**.  
- **https** module for SSL operations.  
- **whois-json** module for WHOIS data.  
- **canvas** module for chart generation.  

---

## Installation and Setup:
1. **Clone the repository.**  
2. **Install dependencies:**  
   npm install

   Set your Telegram bot token in the TOKEN variable
(replace the placeholder YOUR_BOT_TOKEN in the code).
Start the bot:
node index.js

---

## How to Use:
Send a URL (e.g., https://example.com) to the bot in Telegram.
The bot will return:
SSL certificate details.
A chart showing expiration dates.
WHOIS information.
Notes:
The URL must start with http:// or https://.
The chart image is automatically deleted after being sent.
Requirements:
Node.js >= 14.
Telegram Bot API token.
