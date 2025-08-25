const dotenv = require('dotenv');
dotenv.config();
const Bot = require('node-telegram-bot-api');

const token = process.env.TELEGRAM_BOT_TOKEN;
const webUrl = process.env.WEBAPP_URL;

if (!token) {
  console.error('Please set TELEGRAM_BOT_TOKEN in .env');
  process.exit(1);
}
if (!webUrl) {
  console.error('Please set WEBAPP_URL in .env');
  process.exit(1);
}

const bot = new Bot(token, { polling: true });

bot.onText(/\/start/, (msg) => {
  const chatId = msg.chat.id;
  bot.sendMessage(chatId, 'Welcome to Telegram SSI Wallet', {
    reply_markup: {
      inline_keyboard: [[
        { text: 'Open Wallet', web_app: { url: webUrl } }
      ]]
    }
  });
});

console.log('Bot is running. Talk to it on Telegram.');
