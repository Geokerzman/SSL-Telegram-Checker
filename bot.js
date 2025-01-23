const TelegramBot = require('node-telegram-bot-api');
const https = require('https');
const fs = require('fs');
const whois = require('whois-json');
const { createCanvas } = require('canvas');
const axios = require('axios');

const TOKEN = '';
const bot = new TelegramBot(TOKEN, { polling: true });

console.log('Бот запущен и готов к работе...');

async function checkWebsiteSpeed(url) {
  const start = Date.now();
  try {
    const response = await axios.get(url, { timeout: 10000 });
    const ttfb = Date.now() - start; // Time to First Byte
    return {
      status: response.status,
      ttfb,
      totalTime: Date.now() - start,
    };
  } catch (error) {
    throw new Error('Сайт недоступен или истекло время ожидания');
  }
}

async function checkSSL(hostname) {
  return new Promise((resolve, reject) => {
    const options = {
      method: 'HEAD',
      host: hostname,
      port: 443,
      agent: false,
      rejectUnauthorized: false,
    };

    const req = https.request(options, (res) => {
      const certChain = [];
      let cert = res.socket.getPeerCertificate(true);

      while (cert) {
        certChain.push({
          commonName: cert.subject?.CN || 'N/A',
          issuer: cert.issuer?.CN || 'N/A',
          validFrom: cert.valid_from,
          validTo: cert.valid_to,
          isExpired: new Date(cert.valid_to) < new Date(),
          daysUntilExpiration: Math.ceil((new Date(cert.valid_to) - new Date()) / (1000 * 60 * 60 * 24)),
        });
        cert = cert.issuerCertificate && cert !== cert.issuerCertificate ? cert.issuerCertificate : null;
      }

      if (certChain.length === 0) {
        return reject(new Error('Сертификат не найден'));
      }
      resolve(certChain);
    });

    req.on('error', (err) => reject(err));
    req.end();
  });
}

//  WHOIS
async function getWhoisInfo(domain) {
  try {
    const whoisData = await whois(domain);
    return {
      registrar: whoisData.registrar || 'N/A',
      creationDate: whoisData.creationDate || 'N/A',
      expirationDate: whoisData.registryExpiryDate || 'N/A',
    };
  } catch (error) {
    throw new Error('Не удалось получить информацию WHOIS');
  }
}

function generateExpirationChart(certChain) {
  const width = 800; // Ширина изображения
  const height = 400; // Высота изображения
  const canvas = createCanvas(width, height);
  const ctx = canvas.getContext('2d');

  // Параметры графика
  const padding = 50;
  const titleHeight = 40; // Высота области для заголовка
  const chartWidth = width - padding * 2;
  const chartHeight = height - padding - titleHeight;
  const barGap = 20;
  const barWidth = Math.max((chartWidth - barGap * (certChain.length - 1)) / certChain.length, 30);
  const maxBarHeight = chartHeight;


  ctx.fillStyle = '#2e2e2e';
  ctx.fillRect(0, 0, width, height);

  const gridLines = 5;
  ctx.strokeStyle = '#4d4d4d'; // Цвет сетки
  ctx.lineWidth = 1;
  for (let i = 0; i <= gridLines; i++) {
    const y = padding + titleHeight + (i * chartHeight) / gridLines;
    ctx.beginPath();
    ctx.moveTo(padding, y);
    ctx.lineTo(width - padding, y);
    ctx.stroke();
  }
//Heading if needed
  ctx.fillStyle = '#ffffff';
  ctx.font = '20px Arial';
  ctx.textAlign = 'left';

  const maxDays = Math.max(...certChain.map(cert => cert.daysUntilExpiration));

  // poles
  certChain.forEach((cert, index) => {
    const x = padding + index * (barWidth + barGap);
    const barHeight = (cert.daysUntilExpiration / maxDays) * maxBarHeight;
    const y = height - padding - barHeight;

    const gradient = ctx.createLinearGradient(x, y, x + barWidth, height - padding);
    gradient.addColorStop(0, cert.isExpired ? '#ff4d4d' : '#4caf50');
    gradient.addColorStop(1, '#333333');
    ctx.fillStyle = gradient;


    ctx.fillRect(x, y, barWidth, barHeight);

    // pole names
    ctx.fillStyle = '#ffffff';
    ctx.font = '14px Arial';
    ctx.textAlign = 'center';

    // cert name
    ctx.fillText(cert.commonName, x + barWidth / 2, height - padding + 20);

// days until
    const textY = Math.max(y - 10, padding + titleHeight + 15);
    ctx.fillText(`${cert.daysUntilExpiration} дней`, x + barWidth / 2, textY);
  });

  return canvas.toBuffer();
}



// messages
bot.on('message', async (msg) => {
  const chatId = msg.chat.id;
  const text = msg.text;

  if (!text.startsWith('http://') && !text.startsWith('https://')) {
    return bot.sendMessage(chatId, 'Пожалуйста, отправьте URL-адрес, начинающийся с http:// или https://');
  }

  let hostname;
  try {
    const url = new URL(text);
    hostname = url.hostname;
  } catch {
    return bot.sendMessage(chatId, 'Неверный формат URL. Убедитесь, что адрес указан корректно.');
  }

  try {
    const certChain = await checkSSL(hostname);
    let message = `🔒 *SSL Checker для ${hostname}:*\n\n`;

    certChain.forEach((cert, index) => {
      message += `——— *Сертификат ${index + 1}:* ———\n`;
      message += `🔹 Common Name (CN): \`${cert.commonName}\`\n`;
      message += `🔹 Issuer: \`${cert.issuer}\`\n`;
      message += `🔹 Valid From: \`${cert.validFrom}\`\n`;
      message += `🔹 Valid To: \`${cert.validTo}\`\n`;
      message += `🔹 Expired: ${cert.isExpired ? '❌ Да' : '✅ Нет'}\n`;
      message += `🔹 Days Until Expiration: \`${cert.daysUntilExpiration} дней\`\n\n`;
    });

    const speedInfo = await checkWebsiteSpeed(text);
    message += `🚀 *Скорость загрузки сайта:*\n`;
    message += `🔹 HTTP Status: \`${speedInfo.status}\`\n`;
    message += `🔹 TTFB (Time to First Byte): \`${speedInfo.ttfb} мс\`\n`;
    message += `🔹 Время полной загрузки: \`${speedInfo.totalTime} мс\`\n\n`;


    //  WHOIS
    const whoisInfo = await getWhoisInfo(hostname);
    message += `🌐 *Информация о домене:*\n`;
    message += `🔹 Registrar: \`${whoisInfo.registrar}\`\n`;
    message += `🔹 Дата регистрации: \`${whoisInfo.creationDate}\`\n`;
    message += `🔹 Дата истечения: \`${whoisInfo.expirationDate}\`\n`;

    // graphs
    const chartBuffer = generateExpirationChart(certChain);
    const chartFileName = `chart_${hostname}.png`;
    fs.writeFileSync(chartFileName, chartBuffer);

    // send graph and photo
    await bot.sendMessage(chatId, message, { parse_mode: 'Markdown' });
    await bot.sendPhoto(chatId, chartFileName);
    fs.unlinkSync(chartFileName); //delete after sent
  } catch (error) {
    bot.sendMessage(chatId, `Ошибка: ${error.message}`);
  }
});
