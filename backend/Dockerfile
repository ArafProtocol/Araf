#  Alpine Linux tabanlı, hafif ve güvenli bir Node.js imajı.
FROM node:18-alpine

# Uygulama için çalışma dizini oluştur
WORKDIR /usr/src/app

# Bağımlılıkları kurmak için package dosyalarını kopyala
# Bu katman, kod değişmediği sürece cache'lenir ve build hızını artırır.
COPY package*.json ./

# Sadece production bağımlılıklarını kur
RUN npm install --production

# Uygulama kodunun tamamını kopyala
COPY . .

# Uygulamanın çalışacağı portu belirt
EXPOSE 4000

# Uygulamayı başlat
# app.js, process.env.PORT'u dinleyecek şekilde ayarlandi.
CMD [ "node", "scripts/app.js" ]
